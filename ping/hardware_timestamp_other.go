//go:build !linux

package ping

import (
	"errors"
	"log"
	"time"

	"golang.org/x/sys/unix"
)

// ErrStampNotFund is returned when timestamp not found in ancillary data.
var ErrStampNotFund = errors.New("timestamp not found")

func getTimestampFromOOB(_ []byte, _ int) (int64, error) {
	return 0, ErrStampNotFund
}

func getTxTimestamp(_ int) (int64, error) {
	return 0, ErrStampNotFund
}

func configureTimestamps(_ int, iface string, verbose bool, logger *log.Logger, supportTxTS, supportRxTS *bool) error {
	// macOS does not support SO_TIMESTAMPING/HWTSTAMP.
	// Fall back to clock-based timestamps in the receive path.
	*supportTxTS = false
	*supportRxTS = false
	return nil
}

func setSocketTimeouts(fd int, timeout time.Duration) error {
	sec := int64(timeout / time.Second)
	usec := int64(timeout % time.Second / time.Microsecond)
	if sec == 0 && usec == 0 {
		sec = 1
	}
	tv := unix.Timeval{Sec: sec, Usec: int32(usec)}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return err
	}
	return unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv)
}
