// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ios && !ts_omit_vxlanmirror

package condregister

import _ "tailscale.com/feature/vxlanmirror"
