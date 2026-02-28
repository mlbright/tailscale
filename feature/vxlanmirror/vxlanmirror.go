// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package vxlanmirror replicates WireGuard packets to a downstream
// collector over a VXLAN tunnel. Handshake packets (types 1, 2, 3) are
// always sent in their entirety. Transport data packets (type 4) are
// truncated to just the 16-byte WireGuard header by default; with
// full-packet mode enabled the entire encrypted payload is sent.
package vxlanmirror

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"

	"tailscale.com/feature"
	"tailscale.com/ipn/localapi"
	"tailscale.com/net/packet"
	"tailscale.com/types/logger"
)

func init() {
	feature.Register("vxlanmirror")
	localapi.Register("debug-vxlan-mirror", serveLocalAPIDebugVXLANMirror)
}

// WireGuard message types (little-endian uint32 at offset 0).
// See https://www.wireguard.com/protocol/
const (
	wgTypeInitiation  = 1 // Handshake Initiation
	wgTypeResponse    = 2 // Handshake Response
	wgTypeCookieReply = 3 // Cookie Reply
	wgTypeTransport   = 4 // Transport Data
)

// wgTransportHeaderLen is the size of the WireGuard transport data message
// header. Layout: message type (4 bytes) + receiver index (4 bytes) +
// counter (8 bytes). When truncating type-4 packets we keep exactly this
// header and discard the encrypted payload and poly1305 authentication tag.
const wgTransportHeaderLen = 16

// vxlanHeaderLen is the standard VXLAN header size: 8 bytes.
const vxlanHeaderLen = 8

// innerEthHeaderLen is the size of the synthetic Ethernet header
// prepended inside the VXLAN frame (dst MAC + src MAC + EtherType).
const innerEthHeaderLen = 14

// innerIPv4HeaderLen is the minimum IPv4 header length (no options).
const innerIPv4HeaderLen = 20

// innerIPv6HeaderLen is the fixed IPv6 header length.
const innerIPv6HeaderLen = 40

// innerUDPHeaderLen is the standard UDP header length.
const innerUDPHeaderLen = 8

// innerOverhead4 is the inner framing for IPv4 endpoints:
// Ethernet (14) + IPv4 (20) + UDP (8) = 42 bytes.
const innerOverhead4 = innerEthHeaderLen + innerIPv4HeaderLen + innerUDPHeaderLen

// innerOverhead6 is the inner framing for IPv6 endpoints:
// Ethernet (14) + IPv6 (40) + UDP (8) = 62 bytes.
const innerOverhead6 = innerEthHeaderLen + innerIPv6HeaderLen + innerUDPHeaderLen

// innerOverhead returns the total inner framing size for the given address.
func innerOverhead(addr netip.Addr) int {
	if addr.Is6() && !addr.Is4In6() {
		return innerOverhead6
	}
	return innerOverhead4
}

// wgCaptureLen returns how many bytes of a WireGuard packet should be
// mirrored. Handshake packets (types 1, 2, 3) are always preserved in
// their entirety because they contain no user data. Transport data
// packets (type 4) are truncated to wgTransportHeaderLen unless
// full-packet mode is enabled.
func wgCaptureLen(payload []byte, full bool) int {
	if full || len(payload) < 4 {
		return len(payload)
	}
	msgType := binary.LittleEndian.Uint32(payload[:4])
	switch msgType {
	case wgTypeInitiation, wgTypeResponse, wgTypeCookieReply:
		return len(payload)
	default: // wgTypeTransport and anything unknown
		return min(len(payload), wgTransportHeaderLen)
	}
}

// Mirror sends copies of WireGuard packets to a remote collector via VXLAN.
// It is safe for concurrent use.
type Mirror struct {
	logf logger.Logf

	// full, when true, sends the complete encrypted WireGuard packet
	// instead of truncating to wgHeaderLen bytes.
	full atomic.Bool

	mu   sync.Mutex // guards conn, dst, running
	conn *net.UDPConn
	dst  netip.AddrPort
	vni  uint32 // 24-bit VXLAN Network Identifier
}

// NewMirror creates a new (stopped) mirror. Call Start to begin replication.
func NewMirror(logf logger.Logf) *Mirror {
	return &Mirror{logf: logf}
}

// Start begins mirroring packets to the given collector address using the
// specified VXLAN Network Identifier (VNI). If already running, it stops and
// restarts with the new configuration.
func (m *Mirror) Start(dst netip.AddrPort, vni uint32, fullPacket bool) error {
	m.Stop()

	network := "udp4"
	if dst.Addr().Is6() {
		network = "udp6"
	}
	conn, err := net.DialUDP(network, nil, net.UDPAddrFromAddrPort(dst))
	if err != nil {
		return fmt.Errorf("vxlanmirror: dial %v: %w", dst, err)
	}

	m.mu.Lock()
	m.conn = conn
	m.dst = dst
	m.vni = vni & 0x00FFFFFF // mask to 24 bits
	m.full.Store(fullPacket)
	m.mu.Unlock()

	m.logf("vxlanmirror: started mirroring to %v VNI=%d full=%v", dst, vni, fullPacket)
	return nil
}

// Stop halts packet mirroring and closes the UDP socket.
func (m *Mirror) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.conn != nil {
		m.conn.Close()
		m.conn = nil
		m.logf("vxlanmirror: stopped")
	}
}

// Running reports whether the mirror is currently active.
func (m *Mirror) Running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.conn != nil
}

// SetFullPacket enables or disables full-packet mode at runtime.
func (m *Mirror) SetFullPacket(full bool) {
	m.full.Store(full)
}

// MirrorCallback returns the callback suitable for installing on the engine.
func (m *Mirror) MirrorCallback() packet.MirrorCallback {
	return m.SendBatch
}

// Status returns the current configuration/status of the mirror.
func (m *Mirror) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.conn == nil {
		return Status{}
	}
	return Status{
		Running:     true,
		Destination: m.dst.String(),
		VNI:         m.vni,
		FullPacket:  m.full.Load(),
	}
}

// SendPacket replicates a single WireGuard packet to the collector.
// It is designed to be called on the hot path; it returns quickly if
// the mirror is not running. The data slice is not retained.
//
// The offset parameter indicates where the WireGuard payload starts
// within the buffer (matching the wireguard-go Bind.Send offset convention).
// src and dst are the WireGuard tunnel UDP endpoints used to build
// the synthetic inner IP+UDP headers.
func (m *Mirror) SendPacket(buf []byte, offset int, src, dst netip.AddrPort) {
	m.mu.Lock()
	conn := m.conn
	vni := m.vni
	m.mu.Unlock()

	if conn == nil {
		return
	}

	payload := buf[offset:]
	if len(payload) == 0 {
		return
	}

	// Determine how many bytes of the WG packet to mirror.
	captureLen := wgCaptureLen(payload, m.full.Load())

	// Build VXLAN-encapsulated packet:
	// [VXLAN (8)] [Eth+IP+UDP (overhead)] [WG data (captureLen)]
	overhead := innerOverhead(src.Addr())
	pkt := make([]byte, vxlanHeaderLen+overhead+captureLen)
	writeVXLANHeader(pkt, vni)
	writeInnerHeaders(pkt[vxlanHeaderLen:], src, dst, payload[:captureLen])
	copy(pkt[vxlanHeaderLen+overhead:], payload[:captureLen])

	_, _ = conn.Write(pkt)
}

// SendBatch replicates a batch of WireGuard packets. This is the
// primary entry point called from the Send path.
func (m *Mirror) SendBatch(buffs [][]byte, offset int, src, dst netip.AddrPort) {
	m.mu.Lock()
	conn := m.conn
	vni := m.vni
	m.mu.Unlock()

	if conn == nil {
		return
	}

	full := m.full.Load()
	overhead := innerOverhead(src.Addr())

	for _, buf := range buffs {
		payload := buf[offset:]
		if len(payload) == 0 {
			continue
		}

		captureLen := wgCaptureLen(payload, full)

		pkt := make([]byte, vxlanHeaderLen+overhead+captureLen)
		writeVXLANHeader(pkt, vni)
		writeInnerHeaders(pkt[vxlanHeaderLen:], src, dst, payload[:captureLen])
		copy(pkt[vxlanHeaderLen+overhead:], payload[:captureLen])

		_, _ = conn.Write(pkt)
	}
}

// writeVXLANHeader writes the 8-byte VXLAN header at the start of pkt.
func writeVXLANHeader(pkt []byte, vni uint32) {
	pkt[0] = 0x08 // I flag (VNI present)
	pkt[4] = byte(vni >> 16)
	pkt[5] = byte(vni >> 8)
	pkt[6] = byte(vni)
}

// writeInnerHeaders writes the synthetic Ethernet + IP + UDP headers
// into buf. For IPv4 endpoints buf must be at least innerOverhead4 bytes;
// for IPv6 endpoints at least innerOverhead6 bytes. wgPayload is the
// WireGuard data that will follow the headers; it is needed to compute
// the UDP checksum (mandatory for IPv6).
func writeInnerHeaders(buf []byte, src, dst netip.AddrPort, wgPayload []byte) {
	if src.Addr().Is6() && !src.Addr().Is4In6() {
		writeInnerHeaders6(buf, src, dst, wgPayload)
	} else {
		writeInnerHeaders4(buf, src, dst, len(wgPayload))
	}
}

// writeInnerHeaders4 writes Ethernet + IPv4 + UDP headers.
func writeInnerHeaders4(buf []byte, src, dst netip.AddrPort, wgLen int) {
	// --- Ethernet header (14 bytes) ---
	// dst MAC [0:6] and src MAC [6:12] left as zero.
	// EtherType = IPv4 (0x0800)
	buf[12] = 0x08
	buf[13] = 0x00

	// --- IPv4 header (20 bytes) ---
	ip := buf[innerEthHeaderLen:]
	udpTotalLen := innerUDPHeaderLen + wgLen
	ipTotalLen := innerIPv4HeaderLen + udpTotalLen

	ip[0] = 0x45 // version=4, IHL=5 (20 bytes)
	// ip[1] = 0  // DSCP/ECN
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipTotalLen)) // total length
	// ip[4:6] identification = 0
	// ip[6:8] flags/fragment = 0
	ip[8] = 64 // TTL
	ip[9] = 17 // protocol = UDP
	// ip[10:12] checksum — filled below

	srcIP := src.Addr().As4()
	dstIP := dst.Addr().As4()
	copy(ip[12:16], srcIP[:])
	copy(ip[16:20], dstIP[:])

	// IPv4 header checksum.
	binary.BigEndian.PutUint16(ip[10:12], ipv4Checksum(ip[:innerIPv4HeaderLen]))

	// --- UDP header (8 bytes) ---
	u := ip[innerIPv4HeaderLen:]
	binary.BigEndian.PutUint16(u[0:2], src.Port())
	binary.BigEndian.PutUint16(u[2:4], dst.Port())
	binary.BigEndian.PutUint16(u[4:6], uint16(udpTotalLen))
	// u[6:8] checksum = 0 (optional for UDP over IPv4)
}

// writeInnerHeaders6 writes Ethernet + IPv6 + UDP headers.
func writeInnerHeaders6(buf []byte, src, dst netip.AddrPort, wgPayload []byte) {
	// --- Ethernet header (14 bytes) ---
	// dst MAC [0:6] and src MAC [6:12] left as zero.
	// EtherType = IPv6 (0x86DD)
	buf[12] = 0x86
	buf[13] = 0xDD

	// --- IPv6 header (40 bytes) ---
	ip := buf[innerEthHeaderLen:]
	udpTotalLen := innerUDPHeaderLen + len(wgPayload)

	// Version (4) + Traffic Class (8) + Flow Label (20) = 4 bytes.
	// Version = 6 → first nibble 0x6.
	ip[0] = 0x60
	// ip[1], ip[2], ip[3] = 0 (traffic class + flow label)

	// Payload length: UDP header + WG payload (does not include the 40-byte IPv6 header).
	binary.BigEndian.PutUint16(ip[4:6], uint16(udpTotalLen))
	ip[6] = 17 // Next Header = UDP
	ip[7] = 64 // Hop Limit

	srcIP := src.Addr().As16()
	dstIP := dst.Addr().As16()
	copy(ip[8:24], srcIP[:])
	copy(ip[24:40], dstIP[:])

	// --- UDP header (8 bytes) ---
	u := ip[innerIPv6HeaderLen:]
	binary.BigEndian.PutUint16(u[0:2], src.Port())
	binary.BigEndian.PutUint16(u[2:4], dst.Port())
	binary.BigEndian.PutUint16(u[4:6], uint16(udpTotalLen))
	// u[6:8] checksum — mandatory for UDP/IPv6 (RFC 2460 §8.1).
	// Computed over the IPv6 pseudo-header + UDP header + payload.
	// The payload isn't written yet, so we checksum only the pseudo-header
	// and the UDP header (with checksum field zero); the caller copies the
	// WireGuard bytes after this returns, so we include them via the
	// passed-in wgPayload slice.
	binary.BigEndian.PutUint16(u[6:8], udp6Checksum(srcIP[:], dstIP[:], u[:innerUDPHeaderLen], wgPayload))
}

// ipv4Checksum computes the one's-complement checksum over a 20-byte
// IPv4 header (with the checksum field set to zero).
func ipv4Checksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i < len(hdr)-1; i += 2 {
		sum += uint32(hdr[i])<<8 | uint32(hdr[i+1])
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// udp6Checksum computes the UDP checksum over the IPv6 pseudo-header,
// the UDP header (with checksum field zero), and the UDP payload.
// Per RFC 2460 §8.1 a computed value of 0x0000 must be sent as 0xFFFF.
func udp6Checksum(srcIP, dstIP, udpHeader, payload []byte) uint16 {
	var sum uint32

	// IPv6 pseudo-header: src (16) + dst (16) + UDP length (4) + next header (4).
	sum += onesSum(srcIP)
	sum += onesSum(dstIP)
	udpLen := uint32(len(udpHeader) + len(payload))
	sum += udpLen // UDP length as 32-bit (upper 16 bits are zero for any realistic size)
	sum += 17     // next header = UDP

	// UDP header (checksum field at bytes 6-7 is zero at this point).
	sum += onesSum(udpHeader)

	// UDP payload (the WireGuard data).
	sum += onesSum(payload)

	// Fold 32-bit sum into 16 bits.
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	csum := ^uint16(sum)
	if csum == 0 {
		csum = 0xffff
	}
	return csum
}

// onesSum returns the ones-complement (32-bit accumulator) sum of b,
// treating it as a sequence of big-endian 16-bit words. If b has an
// odd length the last byte is padded with a zero byte on the right.
func onesSum(b []byte) uint32 {
	var sum uint32
	for i := 0; i < len(b)-1; i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 != 0 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

// Config is the JSON-encodable configuration for the VXLAN mirror,
// used by the localapi endpoint.
type Config struct {
	// Enabled starts or stops the mirror.
	Enabled bool `json:"enabled"`
	// Destination is the collector's host:port (UDP).
	Destination string `json:"destination,omitempty"`
	// VNI is the VXLAN Network Identifier (0-16777215).
	VNI uint32 `json:"vni,omitzero"`
	// FullPacket sends the entire encrypted WireGuard packet when true.
	// When false (default), only the WireGuard header is sent.
	FullPacket bool `json:"fullPacket,omitzero"`
}

// Status reports the current state of the mirror.
type Status struct {
	Running     bool   `json:"running"`
	Destination string `json:"destination,omitempty"`
	VNI         uint32 `json:"vni,omitzero"`
	FullPacket  bool   `json:"fullPacket,omitzero"`
}

func serveLocalAPIDebugVXLANMirror(h *localapi.Handler, w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "debug access denied", http.StatusForbidden)
		return
	}
	b := h.LocalBackend()

	switch r.Method {
	case "GET":
		mirror := b.GetVXLANMirror()
		var st Status
		if mirror != nil && mirror.Running() {
			// The interface doesn't expose Status() directly, but
			// we know the concrete type here.
			if m, ok := mirror.(*Mirror); ok {
				st = m.Status()
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(st)

	case "POST":
		var cfg Config
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !cfg.Enabled {
			b.StopVXLANMirror()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(Status{Running: false})
			return
		}
		if cfg.Destination == "" {
			http.Error(w, "destination is required", http.StatusBadRequest)
			return
		}
		dst, err := netip.ParseAddrPort(cfg.Destination)
		if err != nil {
			http.Error(w, "invalid destination: "+err.Error(), http.StatusBadRequest)
			return
		}
		if cfg.VNI > 0x00FFFFFF {
			http.Error(w, "VNI must be 0-16777215", http.StatusBadRequest)
			return
		}

		// Ensure the mirror is created and registered with the backend.
		if m := b.GetVXLANMirror(); m == nil {
			b.SetVXLANMirror(NewMirror(b.Logger()))
		}

		if err := b.StartVXLANMirror(dst, cfg.VNI, cfg.FullPacket); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(Status{
			Running:     true,
			Destination: dst.String(),
			VNI:         cfg.VNI,
			FullPacket:  cfg.FullPacket,
		})

	default:
		http.Error(w, "GET or POST required", http.StatusMethodNotAllowed)
	}
}

