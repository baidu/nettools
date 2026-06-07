package ping6

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ErrStampNotFund is returned when timestamp not found in ancillary data.
var ErrStampNotFund = fmt.Errorf("timestamp not found")

// ifreq struct for ioctl calls (SIOCSHWTSTAMP / SIOCGHWTSTAMP).
type ifreq struct {
	name [16]byte
	data uintptr
}

// enableHardwareTimestamp enables hardware timestamping on the given network interface.
func enableHardwareTimestamp(interfaceName string) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("failed to create socket: %w", err)
	}
	defer func() { _ = syscall.Close(fd) }()

	config := unix.HwTstampConfig{
		Flags:     0,
		Tx_type:   unix.HWTSTAMP_TX_ON,      // enable TX timestamps
		Rx_filter: unix.HWTSTAMP_FILTER_ALL, // enable RX timestamps
	}

	var ifr ifreq
	copy(ifr.name[:], interfaceName)
	ifr.data = uintptr(unsafe.Pointer(&config))

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		unix.SIOCSHWTSTAMP,
		uintptr(unsafe.Pointer(&ifr)),
	)
	if errno != 0 {
		return fmt.Errorf("failed to enable hardware timestamp on %s: %v", interfaceName, errno)
	}
	return nil
}

// checkHardwareTimestamp reads and prints the hardware timestamp status.
func checkHardwareTimestamp(interfaceName string) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("failed to create socket: %w", err)
	}
	defer func() { _ = syscall.Close(fd) }()

	var config unix.HwTstampConfig

	var ifr ifreq
	copy(ifr.name[:], interfaceName)
	ifr.data = uintptr(unsafe.Pointer(&config))

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		unix.SIOCGHWTSTAMP,
		uintptr(unsafe.Pointer(&ifr)),
	)
	if errno != 0 {
		return fmt.Errorf("failed to get hardware timestamp status on %s: %v", interfaceName, errno)
	}

	fmt.Printf("Hardware timestamp status for %s:\n", interfaceName)
	fmt.Printf("  TX Type: %d\n", config.Tx_type)
	fmt.Printf("  RX Filter: %d\n", config.Rx_filter)
	fmt.Printf("  Flags: %d\n", config.Flags)
	return nil
}

// getTimestampFromOOB extracts RX hardware timestamp from socket ancillary data.
// Priority: hardware raw (Ts[2]) > hardware transformed (Ts[1]) > software (Ts[0]).
func getTimestampFromOOB(oob []byte, oobn int) (int64, error) {
	cms, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return 0, err
	}
	for _, cm := range cms {
		if cm.Header.Level == syscall.SOL_SOCKET && cm.Header.Type == syscall.SO_TIMESTAMPING {
			var ts unix.ScmTimestamping
			if err := binary.Read(bytes.NewBuffer(cm.Data), binary.LittleEndian, &ts); err != nil {
				return 0, err
			}
			// Prefer hardware timestamp.
			if ts.Ts[2].Nano() > 0 { // Hardware raw
				return ts.Ts[2].Nano(), nil
			}
			if ts.Ts[1].Nano() > 0 { // Hardware transformed
				return ts.Ts[1].Nano(), nil
			}
			if ts.Ts[0].Nano() > 0 { // Software
				return ts.Ts[0].Nano(), nil
			}
			return 0, ErrStampNotFund
		}

		if cm.Header.Level == syscall.SOL_SOCKET && cm.Header.Type == syscall.SCM_TIMESTAMPNS {
			var t unix.Timespec
			if err := binary.Read(bytes.NewBuffer(cm.Data), binary.LittleEndian, &t); err != nil {
				return 0, err
			}
			return t.Nano(), nil
		}
	}
	return 0, ErrStampNotFund
}

// getTxTimestamp reads a TX hardware timestamp from the socket error queue.
func getTxTimestamp(fd int) (int64, error) {
	pktBuf := make([]byte, 1024)
	oob := make([]byte, 1024)
	_, oobn, _, _, err := syscall.Recvmsg(fd, pktBuf, oob, syscall.MSG_ERRQUEUE|syscall.MSG_DONTWAIT)
	if err != nil {
		return 0, err
	}
	return getTimestampFromOOB(oob, oobn)
}

// configureTimestamps enables hardware and/or software timestamping on the socket.
func configureTimestamps(fd int, iface string, verbose bool, logger *log.Logger, supportTxTS, supportRxTS *bool) error {
	if err := enableHardwareTimestamp(iface); err != nil {
		logger.Printf("[WARN] %v", err)
	}
	if verbose {
		_ = checkHardwareTimestamp(iface)
	}

	flags := unix.SOF_TIMESTAMPING_TX_HARDWARE |
		unix.SOF_TIMESTAMPING_RX_HARDWARE |
		unix.SOF_TIMESTAMPING_RAW_HARDWARE |
		unix.SOF_TIMESTAMPING_SYS_HARDWARE |
		unix.SOF_TIMESTAMPING_SOFTWARE |
		unix.SOF_TIMESTAMPING_OPT_CMSG

	if err := syscall.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TIMESTAMPING, flags); err != nil {
		logger.Printf("[WARN] hardware timestamping not supported: %v", err)
		*supportTxTS = false
		*supportRxTS = false
		// Fallback to software timestamps.
		if err := syscall.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TIMESTAMPNS, 1); err != nil {
			return fmt.Errorf("failed to enable software timestamps: %w", err)
		}
		*supportRxTS = true
	} else {
		*supportTxTS = true
		*supportRxTS = true
	}
	return nil
}

// setSocketTimeouts sets send and receive timeouts on the socket.
func setSocketTimeouts(fd int, timeout time.Duration) error {
	sec := int64(timeout / time.Second)
	usec := int64(timeout % time.Second / time.Microsecond)
	if sec == 0 && usec == 0 {
		sec = 1
	}
	tv := unix.Timeval{Sec: sec, Usec: usec}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return err
	}
	return unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv)
}
