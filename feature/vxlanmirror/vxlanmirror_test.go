// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vxlanmirror

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"

	"tailscale.com/types/logger"
)

// test addresses for the synthetic inner IP+UDP headers.
var (
	testSrc = netip.MustParseAddrPort("192.168.1.1:41641")
	testDst = netip.MustParseAddrPort("10.0.0.2:41641")
)

// makeWGPacket builds a fake WireGuard packet of the given total size
// with the message type encoded as a little-endian uint32 in the first
// four bytes (matching the wire format).
func makeWGPacket(msgType uint32, totalLen int) []byte {
	buf := make([]byte, totalLen)
	if totalLen >= 4 {
		binary.LittleEndian.PutUint32(buf[:4], msgType)
	}
	for i := 4; i < totalLen; i++ {
		buf[i] = byte(i)
	}
	return buf
}

func TestMirrorStartStop(t *testing.T) {
	m := NewMirror(logger.Discard)
	if m.Running() {
		t.Fatal("mirror should not be running initially")
	}

	// Start a UDP listener to receive mirrored packets.
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	dst := netip.MustParseAddrPort(pc.LocalAddr().String())

	if err := m.Start(dst, 42, false); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	if !m.Running() {
		t.Fatal("mirror should be running after Start")
	}

	m.Stop()
	if m.Running() {
		t.Fatal("mirror should not be running after Stop")
	}
}

func TestMirrorSendPacketHeaderOnly(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	dst := netip.MustParseAddrPort(pc.LocalAddr().String())

	m := NewMirror(logger.Discard)
	if err := m.Start(dst, 100, false); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer m.Stop()

	// Create a fake WireGuard transport (type 4) packet (64 bytes, offset 0).
	wgPacket := makeWGPacket(wgTypeTransport, 64)

	m.SendPacket(wgPacket, 0, testSrc, testDst)

	// Read the mirrored packet.
	buf := make([]byte, 1500)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	pkt := buf[:n]

	// Should be VXLAN (8) + Eth (14) + IP (20) + UDP (8) + wgTransportHeaderLen (16) = 66 bytes.
	if n != vxlanHeaderLen+innerOverhead4+wgTransportHeaderLen {
		t.Fatalf("expected %d bytes, got %d", vxlanHeaderLen+innerOverhead4+wgTransportHeaderLen, n)
	}

	// Check VXLAN header.
	if pkt[0] != 0x08 {
		t.Errorf("VXLAN I flag: got %#x, want 0x08", pkt[0])
	}
	// VNI = 100 = 0x000064
	gotVNI := uint32(pkt[4])<<16 | uint32(pkt[5])<<8 | uint32(pkt[6])
	if gotVNI != 100 {
		t.Errorf("VNI: got %d, want 100", gotVNI)
	}

	// Check inner Ethernet header EtherType = IPv4.
	gotEther := uint16(pkt[vxlanHeaderLen+12])<<8 | uint16(pkt[vxlanHeaderLen+13])
	if gotEther != 0x0800 {
		t.Errorf("inner EtherType: got %#x, want 0x0800", gotEther)
	}

	// Check inner IPv4 header.
	ipOff := vxlanHeaderLen + innerEthHeaderLen
	if pkt[ipOff] != 0x45 {
		t.Errorf("IP version/IHL: got %#x, want 0x45", pkt[ipOff])
	}
	if pkt[ipOff+9] != 17 {
		t.Errorf("IP protocol: got %d, want 17 (UDP)", pkt[ipOff+9])
	}
	gotSrcIP := netip.AddrFrom4([4]byte(pkt[ipOff+12 : ipOff+16]))
	if gotSrcIP != testSrc.Addr() {
		t.Errorf("inner src IP: got %v, want %v", gotSrcIP, testSrc.Addr())
	}
	gotDstIP := netip.AddrFrom4([4]byte(pkt[ipOff+16 : ipOff+20]))
	if gotDstIP != testDst.Addr() {
		t.Errorf("inner dst IP: got %v, want %v", gotDstIP, testDst.Addr())
	}

	// Check inner UDP header.
	udpOff := ipOff + innerIPv4HeaderLen
	gotSrcPort := binary.BigEndian.Uint16(pkt[udpOff : udpOff+2])
	if gotSrcPort != testSrc.Port() {
		t.Errorf("inner src port: got %d, want %d", gotSrcPort, testSrc.Port())
	}
	gotDstPort := binary.BigEndian.Uint16(pkt[udpOff+2 : udpOff+4])
	if gotDstPort != testDst.Port() {
		t.Errorf("inner dst port: got %d, want %d", gotDstPort, testDst.Port())
	}

	// Check payload contains only the first 16 bytes (WG transport header).
	payloadOff := vxlanHeaderLen + innerOverhead4
	for i := range wgTransportHeaderLen {
		if pkt[payloadOff+i] != wgPacket[i] {
			t.Errorf("payload[%d] = %d, want %d", i, pkt[payloadOff+i], wgPacket[i])
		}
	}
}

func TestMirrorSendPacketFullMode(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	dst := netip.MustParseAddrPort(pc.LocalAddr().String())

	m := NewMirror(logger.Discard)
	if err := m.Start(dst, 1, true); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer m.Stop()

	wgPacket := makeWGPacket(wgTypeTransport, 128)

	m.SendPacket(wgPacket, 0, testSrc, testDst)

	buf := make([]byte, 1500)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}

	// Full mode: VXLAN (8) + inner overhead (42) + full packet (128) = 178 bytes.
	if n != vxlanHeaderLen+innerOverhead4+128 {
		t.Fatalf("expected %d bytes, got %d", vxlanHeaderLen+innerOverhead4+128, n)
	}

	// Verify full payload.
	payloadOff := vxlanHeaderLen + innerOverhead4
	for i := range 128 {
		if buf[payloadOff+i] != wgPacket[i] {
			t.Errorf("payload[%d] = %d, want %d", i, buf[payloadOff+i], wgPacket[i])
		}
	}
}

func TestMirrorSendBatch(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	dst := netip.MustParseAddrPort(pc.LocalAddr().String())

	m := NewMirror(logger.Discard)
	if err := m.Start(dst, 7, false); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer m.Stop()

	// Create a batch of 3 transport (type 4) packets with offset 4.
	const offset = 4
	buffs := make([][]byte, 3)
	for i := range buffs {
		buf := make([]byte, offset+48)
		binary.LittleEndian.PutUint32(buf[offset:], wgTypeTransport)
		for j := offset + 4; j < len(buf); j++ {
			buf[j] = byte(i*10 + j - offset)
		}
		buffs[i] = buf
	}

	m.SendBatch(buffs, offset, testSrc, testDst)

	// Read all 3 mirrored packets.
	for i := range 3 {
		buf := make([]byte, 1500)
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
		// Transport header-only: 8 + 42 + 16 = 66.
		if n != vxlanHeaderLen+innerOverhead4+wgTransportHeaderLen {
			t.Fatalf("packet %d: expected %d bytes, got %d", i, vxlanHeaderLen+innerOverhead4+wgTransportHeaderLen, n)
		}
	}
}

func TestMirrorWithOffset(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	dst := netip.MustParseAddrPort(pc.LocalAddr().String())

	m := NewMirror(logger.Discard)
	if err := m.Start(dst, 42, false); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer m.Stop()

	// Buffer with offset=16, WG transport packet starts at byte 16.
	const offset = 16
	buf := make([]byte, offset+64)
	// Fill the header area with junk.
	for i := range offset {
		buf[i] = 0xFF
	}
	// Fill the WG payload with a type-4 transport packet.
	binary.LittleEndian.PutUint32(buf[offset:], wgTypeTransport)
	for i := offset + 4; i < len(buf); i++ {
		buf[i] = byte(i - offset)
	}

	m.SendPacket(buf, offset, testSrc, testDst)

	recv := make([]byte, 1500)
	n, _, err := pc.ReadFrom(recv)
	if err != nil {
		t.Fatal(err)
	}
	if n != vxlanHeaderLen+innerOverhead4+wgTransportHeaderLen {
		t.Fatalf("expected %d bytes, got %d", vxlanHeaderLen+innerOverhead4+wgTransportHeaderLen, n)
	}

	// Verify that the captured data is from the WG payload, not the junk header.
	payloadOff := vxlanHeaderLen + innerOverhead4
	for i := range wgTransportHeaderLen {
		if recv[payloadOff+i] != buf[offset+i] {
			t.Errorf("payload[%d] = %d, want %d", i, recv[payloadOff+i], buf[offset+i])
		}
	}
}

func TestMirrorSmallPacket(t *testing.T) {
	// A transport packet smaller than wgTransportHeaderLen should be
	// sent in its entirety (not padded) in header-only mode.
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	dst := netip.MustParseAddrPort(pc.LocalAddr().String())

	m := NewMirror(logger.Discard)
	if err := m.Start(dst, 1, false); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer m.Stop()

	// 8 bytes — smaller than wgTransportHeaderLen=16.
	// Type 4 in the first 4 bytes, then 4 more bytes.
	smallPkt := makeWGPacket(wgTypeTransport, 8)

	m.SendPacket(smallPkt, 0, testSrc, testDst)

	recv := make([]byte, 1500)
	n, _, err := pc.ReadFrom(recv)
	if err != nil {
		t.Fatal(err)
	}
	// Should be 8 + 42 + 8 = 58 (not 66).
	if n != vxlanHeaderLen+innerOverhead4+8 {
		t.Fatalf("expected %d bytes, got %d", vxlanHeaderLen+innerOverhead4+8, n)
	}
}

func TestMirrorVNIMasking(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	dst := netip.MustParseAddrPort(pc.LocalAddr().String())

	m := NewMirror(logger.Discard)
	// VNI with bits beyond 24-bit should be masked.
	if err := m.Start(dst, 0xFF000042, false); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer m.Stop()

	wgPacket := makeWGPacket(wgTypeTransport, 64)
	m.SendPacket(wgPacket, 0, testSrc, testDst)

	recv := make([]byte, 1500)
	n, _, err := pc.ReadFrom(recv)
	if err != nil {
		t.Fatal(err)
	}
	if n < vxlanHeaderLen {
		t.Fatalf("packet too small: %d", n)
	}

	// VNI should be masked to 0x000042 = 66.
	gotVNI := uint32(recv[4])<<16 | uint32(recv[5])<<8 | uint32(recv[6])
	if gotVNI != 0x42 {
		t.Errorf("VNI: got %d (0x%x), want 66 (0x42)", gotVNI, gotVNI)
	}

	// Verify inner Ethernet EtherType = IPv4.
	gotEther := uint16(recv[vxlanHeaderLen+12])<<8 | uint16(recv[vxlanHeaderLen+13])
	if gotEther != 0x0800 {
		t.Errorf("inner EtherType: got %#x, want 0x0800", gotEther)
	}
}

func TestMirrorCallback(t *testing.T) {
	m := NewMirror(logger.Discard)
	cb := m.MirrorCallback()
	if cb == nil {
		t.Fatal("MirrorCallback returned nil")
	}

	// Calling the callback when not running should be safe (no panic).
	buffs := [][]byte{make([]byte, 64)}
	cb(buffs, 0, testSrc, testDst)
}

func TestMirrorSetFullPacketRuntime(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	dst := netip.MustParseAddrPort(pc.LocalAddr().String())

	m := NewMirror(logger.Discard)
	// Start in header-only mode.
	if err := m.Start(dst, 1, false); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer m.Stop()

	wgPacket := makeWGPacket(wgTypeTransport, 64)

	// First packet: header-only (transport type 4 truncated).
	m.SendPacket(wgPacket, 0, testSrc, testDst)
	recv := make([]byte, 1500)
	n, _, _ := pc.ReadFrom(recv)
	if n != vxlanHeaderLen+innerOverhead4+wgTransportHeaderLen {
		t.Fatalf("header-only: expected %d, got %d", vxlanHeaderLen+innerOverhead4+wgTransportHeaderLen, n)
	}

	// Switch to full packet mode.
	m.SetFullPacket(true)
	m.SendPacket(wgPacket, 0, testSrc, testDst)
	n, _, _ = pc.ReadFrom(recv)
	if n != vxlanHeaderLen+innerOverhead4+64 {
		t.Fatalf("full mode: expected %d, got %d", vxlanHeaderLen+innerOverhead4+64, n)
	}

	// Switch back.
	m.SetFullPacket(false)
	m.SendPacket(wgPacket, 0, testSrc, testDst)
	n, _, _ = pc.ReadFrom(recv)
	if n != vxlanHeaderLen+innerOverhead4+wgTransportHeaderLen {
		t.Fatalf("back to header-only: expected %d, got %d", vxlanHeaderLen+innerOverhead4+wgTransportHeaderLen, n)
	}
}

func TestMirrorHandshakePacketsPreservedFull(t *testing.T) {
	// Handshake packets (types 1, 2, 3) must always be mirrored in
	// their entirety, even when full-packet mode is off.
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	dst := netip.MustParseAddrPort(pc.LocalAddr().String())

	m := NewMirror(logger.Discard)
	if err := m.Start(dst, 1, false); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer m.Stop()

	tests := []struct {
		name    string
		msgType uint32
		size    int
	}{
		{"Initiation", wgTypeInitiation, 148},
		{"Response", wgTypeResponse, 92},
		{"CookieReply", wgTypeCookieReply, 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := makeWGPacket(tt.msgType, tt.size)
			m.SendPacket(pkt, 0, testSrc, testDst)

			recv := make([]byte, 1500)
			n, _, err := pc.ReadFrom(recv)
			if err != nil {
				t.Fatal(err)
			}

			// Full packet must be preserved.
			wantLen := vxlanHeaderLen + innerOverhead4 + tt.size
			if n != wantLen {
				t.Fatalf("expected %d bytes, got %d", wantLen, n)
			}

			// Verify the payload matches.
			payloadOff := vxlanHeaderLen + innerOverhead4
			for i := range tt.size {
				if recv[payloadOff+i] != pkt[i] {
					t.Errorf("payload[%d] = %d, want %d", i, recv[payloadOff+i], pkt[i])
					break
				}
			}
		})
	}
}

func TestMirrorHandshakeBatch(t *testing.T) {
	// A batch containing a mix of handshake and transport packets
	// should preserve handshakes fully and truncate transport.
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	dst := netip.MustParseAddrPort(pc.LocalAddr().String())

	m := NewMirror(logger.Discard)
	if err := m.Start(dst, 1, false); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer m.Stop()

	const offset = 4
	initPkt := make([]byte, offset+148)
	binary.LittleEndian.PutUint32(initPkt[offset:], wgTypeInitiation)
	transportPkt := make([]byte, offset+128)
	binary.LittleEndian.PutUint32(transportPkt[offset:], wgTypeTransport)

	m.SendBatch([][]byte{initPkt, transportPkt}, offset, testSrc, testDst)

	// First received: initiation, full (8 + 42 + 148 = 198).
	recv := make([]byte, 1500)
	n, _, err := pc.ReadFrom(recv)
	if err != nil {
		t.Fatal(err)
	}
	if n != vxlanHeaderLen+innerOverhead4+148 {
		t.Fatalf("initiation: expected %d bytes, got %d", vxlanHeaderLen+innerOverhead4+148, n)
	}

	// Second received: transport, truncated (8 + 42 + 16 = 66).
	n, _, err = pc.ReadFrom(recv)
	if err != nil {
		t.Fatal(err)
	}
	if n != vxlanHeaderLen+innerOverhead4+wgTransportHeaderLen {
		t.Fatalf("transport: expected %d bytes, got %d", vxlanHeaderLen+innerOverhead4+wgTransportHeaderLen, n)
	}
}

// IPv6 test addresses for the synthetic inner IP+UDP headers.
var (
	testSrc6 = netip.MustParseAddrPort("[2607:fea8:7c0:5000::76cd]:41641")
	testDst6 = netip.MustParseAddrPort("[2600:1f18:4a93:2700:107e:7ef5:18d1:fb57]:41641")
)

func TestMirrorSendPacketIPv6(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	dst := netip.MustParseAddrPort(pc.LocalAddr().String())

	m := NewMirror(logger.Discard)
	if err := m.Start(dst, 100, false); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer m.Stop()

	wgPacket := makeWGPacket(wgTypeTransport, 64)

	m.SendPacket(wgPacket, 0, testSrc6, testDst6)

	buf := make([]byte, 1500)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	pkt := buf[:n]

	// Should be VXLAN (8) + Eth (14) + IPv6 (40) + UDP (8) + wgTransportHeaderLen (16) = 86 bytes.
	if n != vxlanHeaderLen+innerOverhead6+wgTransportHeaderLen {
		t.Fatalf("expected %d bytes, got %d", vxlanHeaderLen+innerOverhead6+wgTransportHeaderLen, n)
	}

	// Check VXLAN header.
	if pkt[0] != 0x08 {
		t.Errorf("VXLAN I flag: got %#x, want 0x08", pkt[0])
	}
	gotVNI := uint32(pkt[4])<<16 | uint32(pkt[5])<<8 | uint32(pkt[6])
	if gotVNI != 100 {
		t.Errorf("VNI: got %d, want 100", gotVNI)
	}

	// Check inner Ethernet header EtherType = IPv6 (0x86DD).
	gotEther := uint16(pkt[vxlanHeaderLen+12])<<8 | uint16(pkt[vxlanHeaderLen+13])
	if gotEther != 0x86DD {
		t.Errorf("inner EtherType: got %#x, want 0x86DD", gotEther)
	}

	// Check inner IPv6 header.
	ipOff := vxlanHeaderLen + innerEthHeaderLen
	if pkt[ipOff]>>4 != 6 {
		t.Errorf("IP version: got %d, want 6", pkt[ipOff]>>4)
	}
	if pkt[ipOff+6] != 17 {
		t.Errorf("Next Header: got %d, want 17 (UDP)", pkt[ipOff+6])
	}
	gotSrcIP := netip.AddrFrom16([16]byte(pkt[ipOff+8 : ipOff+24]))
	if gotSrcIP != testSrc6.Addr() {
		t.Errorf("inner src IP: got %v, want %v", gotSrcIP, testSrc6.Addr())
	}
	gotDstIP := netip.AddrFrom16([16]byte(pkt[ipOff+24 : ipOff+40]))
	if gotDstIP != testDst6.Addr() {
		t.Errorf("inner dst IP: got %v, want %v", gotDstIP, testDst6.Addr())
	}

	// Check inner UDP header.
	udpOff := ipOff + innerIPv6HeaderLen
	gotSrcPort := binary.BigEndian.Uint16(pkt[udpOff : udpOff+2])
	if gotSrcPort != testSrc6.Port() {
		t.Errorf("inner src port: got %d, want %d", gotSrcPort, testSrc6.Port())
	}
	gotDstPort := binary.BigEndian.Uint16(pkt[udpOff+2 : udpOff+4])
	if gotDstPort != testDst6.Port() {
		t.Errorf("inner dst port: got %d, want %d", gotDstPort, testDst6.Port())
	}

	// UDP checksum must be non-zero for IPv6 (RFC 2460 §8.1).
	gotCsum := binary.BigEndian.Uint16(pkt[udpOff+6 : udpOff+8])
	if gotCsum == 0 {
		t.Error("inner UDP checksum is zero; must be non-zero for IPv6")
	}

	// Verify the checksum: summing the pseudo-header, UDP header, and
	// payload (with the checksum field included) should yield 0xFFFF.
	ipOff2 := vxlanHeaderLen + innerEthHeaderLen
	srcIPBytes := pkt[ipOff2+8 : ipOff2+24]
	dstIPBytes := pkt[ipOff2+24 : ipOff2+40]
	udpBytes := pkt[udpOff : udpOff+innerUDPHeaderLen]
	wgBytes := pkt[vxlanHeaderLen+innerOverhead6 : n]
	if !verifyUDP6Checksum(srcIPBytes, dstIPBytes, udpBytes, wgBytes) {
		t.Errorf("inner UDP checksum %#04x does not verify", gotCsum)
	}

	// Check payload contains only the first 16 bytes (WG transport header).
	payloadOff := vxlanHeaderLen + innerOverhead6
	for i := range wgTransportHeaderLen {
		if pkt[payloadOff+i] != wgPacket[i] {
			t.Errorf("payload[%d] = %d, want %d", i, pkt[payloadOff+i], wgPacket[i])
		}
	}
}

func TestMirrorSendBatchIPv6(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	dst := netip.MustParseAddrPort(pc.LocalAddr().String())

	m := NewMirror(logger.Discard)
	if err := m.Start(dst, 7, false); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer m.Stop()

	const offset = 4
	buffs := make([][]byte, 3)
	for i := range buffs {
		buf := make([]byte, offset+48)
		binary.LittleEndian.PutUint32(buf[offset:], wgTypeTransport)
		buffs[i] = buf
	}

	m.SendBatch(buffs, offset, testSrc6, testDst6)

	for i := range 3 {
		buf := make([]byte, 1500)
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
		// Transport header-only: 8 + 62 + 16 = 86.
		if n != vxlanHeaderLen+innerOverhead6+wgTransportHeaderLen {
			t.Fatalf("packet %d: expected %d bytes, got %d", i, vxlanHeaderLen+innerOverhead6+wgTransportHeaderLen, n)
		}
	}
}

func TestMirrorSendPacketIPv4MappedIPv6(t *testing.T) {
	// IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) should use IPv4 framing.
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	dst := netip.MustParseAddrPort(pc.LocalAddr().String())

	m := NewMirror(logger.Discard)
	if err := m.Start(dst, 1, false); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer m.Stop()

	// ::ffff:192.168.1.1 is IPv4-in-6; should produce IPv4 inner headers.
	src4in6 := netip.MustParseAddrPort("[::ffff:192.168.1.1]:41641")
	dst4in6 := netip.MustParseAddrPort("[::ffff:10.0.0.2]:41641")

	wgPacket := makeWGPacket(wgTypeTransport, 64)
	m.SendPacket(wgPacket, 0, src4in6, dst4in6)

	buf := make([]byte, 1500)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}

	// Should use IPv4 overhead (42), not IPv6 (62).
	if n != vxlanHeaderLen+innerOverhead4+wgTransportHeaderLen {
		t.Fatalf("expected %d bytes, got %d", vxlanHeaderLen+innerOverhead4+wgTransportHeaderLen, n)
	}

	// Check EtherType is IPv4.
	gotEther := uint16(buf[vxlanHeaderLen+12])<<8 | uint16(buf[vxlanHeaderLen+13])
	if gotEther != 0x0800 {
		t.Errorf("inner EtherType: got %#x, want 0x0800", gotEther)
	}
}

// verifyUDP6Checksum checks that the UDP checksum in the header is
// correct by summing the pseudo-header, UDP header (including checksum),
// and payload. A correct checksum produces 0xFFFF.
func verifyUDP6Checksum(srcIP, dstIP, udpHeader, payload []byte) bool {
	var sum uint32
	sum += onesSum(srcIP)
	sum += onesSum(dstIP)
	udpLen := uint32(len(udpHeader) + len(payload))
	sum += udpLen
	sum += 17 // next header = UDP
	sum += onesSum(udpHeader)
	sum += onesSum(payload)
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return uint16(sum) == 0xffff
}
