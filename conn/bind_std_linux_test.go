//go:build linux

package conn

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"testing"

	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

func TestStdNetBindSendRetriesWithoutGSOAfterEMSGSIZE(t *testing.T) {
	bind := NewStdNetBind().(*StdNetBind)
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()

	bind.ipv4 = udpConn
	bind.ipv4TxOffload = true
	bind.ipv6TxOffload = true
	var batchLengths []int
	bind.sendBatch = func(_ *net.UDPConn, _ batchWriter, msgs []ipv6.Message) error {
		batchLengths = append(batchLengths, len(msgs))
		if len(batchLengths) == 1 {
			return &net.OpError{Op: "write", Net: "udp", Err: &os.SyscallError{Syscall: "sendmmsg", Err: unix.EMSGSIZE}}
		}
		return nil
	}

	endpoint := &StdNetEndpoint{AddrPort: netip.MustParseAddrPort("127.0.0.1:51820")}
	err = bind.Send([][]byte{make([]byte, 100), make([]byte, 100), make([]byte, 100)}, endpoint)
	var disabled ErrUDPGSODisabled
	if !errors.As(err, &disabled) || disabled.RetryErr != nil {
		t.Fatalf("Send error = %v, want successful ErrUDPGSODisabled", err)
	}
	if got, want := batchLengths, []int{1, 3}; !slices.Equal(got, want) {
		t.Fatalf("batch lengths = %v, want %v", got, want)
	}
	stats := bind.UDPGSOStats()
	if stats.IPv4Enabled || !stats.IPv6Enabled || stats.IPv4Fallbacks != 1 || stats.IPv4RetryFailures != 0 {
		t.Fatalf("unexpected UDP GSO stats: %+v", stats)
	}
}
