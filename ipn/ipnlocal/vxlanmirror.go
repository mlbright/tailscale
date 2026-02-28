// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"net/netip"

	"tailscale.com/net/packet"
)

// GetVXLANMirror returns the current VXLAN packet mirror, or nil.
func (b *LocalBackend) GetVXLANMirror() packet.PacketMirror {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.vxlanMirror
}

// SetVXLANMirror sets the VXLAN mirror implementation. This is called
// from the vxlanmirror feature package's init to register the mirror.
func (b *LocalBackend) SetVXLANMirror(m packet.PacketMirror) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.vxlanMirror = m
}

// StartVXLANMirror starts packet mirroring to the given destination.
// It installs the mirror hook on the WireGuard engine so that
// outbound encrypted packets are replicated via VXLAN.
func (b *LocalBackend) StartVXLANMirror(dst netip.AddrPort, vni uint32, fullPacket bool) error {
	b.mu.Lock()
	m := b.vxlanMirror
	b.mu.Unlock()

	if m == nil {
		return ErrVXLANMirrorUnavailable
	}

	if err := m.Start(dst, vni, fullPacket); err != nil {
		return err
	}

	b.e.InstallMirrorHook(m.MirrorCallback())
	return nil
}

// StopVXLANMirror stops packet mirroring and uninstalls the engine hook.
func (b *LocalBackend) StopVXLANMirror() {
	b.mu.Lock()
	m := b.vxlanMirror
	b.mu.Unlock()

	if m != nil {
		m.Stop()
	}
	b.e.InstallMirrorHook(nil)
}

// ErrVXLANMirrorUnavailable indicates the vxlanmirror feature is not
// compiled into this binary.
var ErrVXLANMirrorUnavailable = packet.ErrMirrorUnavailable
