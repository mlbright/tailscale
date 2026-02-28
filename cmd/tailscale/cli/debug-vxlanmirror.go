// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ios && !ts_omit_vxlanmirror

package cli

import (
	"context"
	"flag"
	"fmt"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/client/local"
)

func init() {
	debugVXLANMirrorCmd = mkDebugVXLANMirrorCmd
}

func mkDebugVXLANMirrorCmd() *ffcli.Command {
	return &ffcli.Command{
		Name:       "vxlan-mirror",
		ShortUsage: "tailscale debug vxlan-mirror [flags]",
		Exec:       runVXLANMirror,
		ShortHelp:  "Replicate encrypted WireGuard packets to a collector over VXLAN",
		LongHelp: `Replicate outbound encrypted WireGuard packets to a downstream
collector encapsulated in VXLAN. By default, only the WireGuard
header (first 32 bytes) is sent to preserve session metadata
without exposing plaintext. Use --full to send the complete
encrypted packet.`,
		FlagSet: (func() *flag.FlagSet {
			fs := newFlagSet("vxlan-mirror")
			fs.StringVar(&vxlanMirrorArgs.destination, "dst", "", "collector UDP address (host:port)")
			fs.UintVar(&vxlanMirrorArgs.vni, "vni", 1, "VXLAN Network Identifier (0-16777215)")
			fs.BoolVar(&vxlanMirrorArgs.full, "full", false, "send full encrypted packet (default: WG header only)")
			fs.BoolVar(&vxlanMirrorArgs.stop, "stop", false, "stop mirroring")
			fs.BoolVar(&vxlanMirrorArgs.status, "status", false, "show mirror status")
			return fs
		})(),
	}
}

var vxlanMirrorArgs struct {
	destination string
	vni         uint
	full        bool
	stop        bool
	status      bool
}

func runVXLANMirror(ctx context.Context, args []string) error {
	if vxlanMirrorArgs.status {
		st, err := localClient.GetVXLANMirrorStatus(ctx)
		if err != nil {
			return err
		}
		if !st.Running {
			fmt.Fprintln(Stdout, "VXLAN mirror: not running")
			return nil
		}
		fmt.Fprintf(Stdout, "VXLAN mirror: running\n  destination: %s\n  VNI: %d\n  full-packet: %v\n",
			st.Destination, st.VNI, st.FullPacket)
		return nil
	}

	if vxlanMirrorArgs.stop {
		_, err := localClient.SetVXLANMirror(ctx, local.VXLANMirrorConfig{
			Enabled: false,
		})
		if err != nil {
			return err
		}
		fmt.Fprintln(Stdout, "VXLAN mirror stopped.")
		return nil
	}

	if vxlanMirrorArgs.destination == "" {
		return fmt.Errorf("--dst is required (e.g. --dst 10.0.0.1:4789)")
	}
	if vxlanMirrorArgs.vni > 0x00FFFFFF {
		return fmt.Errorf("--vni must be 0-16777215")
	}

	st, err := localClient.SetVXLANMirror(ctx, local.VXLANMirrorConfig{
		Enabled:     true,
		Destination: vxlanMirrorArgs.destination,
		VNI:         uint32(vxlanMirrorArgs.vni),
		FullPacket:  vxlanMirrorArgs.full,
	})
	if err != nil {
		return err
	}
	mode := "header-only (32 bytes)"
	if st.FullPacket {
		mode = "full packet"
	}
	fmt.Fprintf(Stdout, "VXLAN mirror started: %s VNI=%d mode=%s\n", st.Destination, st.VNI, mode)
	return nil
}
