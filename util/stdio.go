package util

import (
	"io"
	"log"
	"net"
	"os"
	"time"
)

// StdioConn implements the net.Conn interface for stdin/stdout.
type StdioConn struct {
	Logger *log.Logger
}

func (s *StdioConn) Read(b []byte) (n int, err error) {
	if s.Logger.Writer() != io.Discard {
		s.Logger.Printf("[STDIO] Reading from stdin...")
	}
	n, err = os.Stdin.Read(b)
	if err != nil {
		if s.Logger.Writer() != io.Discard {
			if err == io.EOF {
				s.Logger.Printf("[STDIO] EOF on stdin.")
			} else {
				s.Logger.Printf("[STDIO] Error reading from stdin: %v", err)
			}
		}
	}
	return n, err
}

func (s *StdioConn) Write(b []byte) (n int, err error) {
	if s.Logger.Writer() != io.Discard {
		s.Logger.Printf("[STDIO] Writing to stdout...")
	}
	n, err = os.Stdout.Write(b)
	if err != nil {
		if s.Logger.Writer() != io.Discard {
			s.Logger.Printf("[STDIO] Error writing to stdout: %v", err)
		}
	}
	return n, err
}

func (s *StdioConn) Close() error {
	if s.Logger.Writer() != io.Discard {
		s.Logger.Printf("[STDIO] Closing stdin/stdout connection.")
	}
	// For stdin/stdout, closing doesn't really do anything meaningful.
	// You might want to close stdin/stdout handles if they were explicitly opened,
	// but here we just return nil.
	return nil
}

func (s *StdioConn) LocalAddr() net.Addr {
	return &net.IPAddr{IP: net.ParseIP("127.0.0.1")}
}

func (s *StdioConn) RemoteAddr() net.Addr {
	return &net.IPAddr{IP: net.ParseIP("127.0.0.1")}
}

func (s *StdioConn) SetDeadline(t time.Time) error {
	return nil // Not applicable for stdin/stdout
}

func (s *StdioConn) SetReadDeadline(t time.Time) error {
	return nil // Not applicable for stdin/stdout
}

func (s *StdioConn) SetWriteDeadline(t time.Time) error {
	return nil // Not applicable for stdin/stdout
}
