/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func errShouldDisableUDPGSO(err error) bool {
	var serr *os.SyscallError
	if errors.As(err, &serr) {
		// EIO is returned by udp_send_skb() if the device driver does not have
		// tx checksumming enabled, which is a hard requirement of UDP_SEGMENT.
		// See:
		// https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git/tree/man7/udp.7?id=806eabd74910447f21005160e90957bde4db0183#n228
		// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/udp.c?h=v6.2&id=c9c3395d5e3dcc6daee66c6908354d47bf98cb0c#n942
		// If gso_size + udp + ip headers > fragment size EINVAL is returned.
		// It occurs when the peer mtu + wg headers is greater than path mtu.
		// EMSGSIZE is returned when the NIC or path cannot accept a UDP_SEGMENT
		// datagram. Retrying the same encrypted packets without GSO is safe and
		// avoids dropping the whole batch on hosts that expose UDP_SEGMENT but do
		// not support it on the selected egress device.
		return serr.Err == unix.EIO || serr.Err == unix.EINVAL || serr.Err == unix.EMSGSIZE
	}
	return false
}
