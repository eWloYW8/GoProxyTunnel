package handlers

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/eWloYW8/GoProxyTunnel/config"
)

// SOCKS5 constants
const (
	socks5Version                      = 0x05
	socks5CmdConnect                   = 0x01
	socks5ATYPIPv4                     = 0x01
	socks5ATYPDomain                   = 0x03
	socks5ATYPIPv6                     = 0x04
	socks5ReplySuccess                 = 0x00
	socks5ReplyGeneralFailure          = 0x01
	socks5ReplyCommandNotSupported     = 0x03
	socks5ReplyAddressTypeNotSupported = 0x08
)

// HandleSocks5 manages a SOCKS5 client connection, determines the target, and then uses HTTP CONNECT.
func HandleSocks5(clientConn net.Conn, cfg *config.Config, logger *log.Logger) {
	defer clientConn.Close()
	clientAddr := clientConn.RemoteAddr()

	logger.Printf("[%s] Accepted SOCKS5 connection from %s", clientAddr, clientAddr)
	reader := bufio.NewReader(clientConn)

	// SOCKS5 Handshake: Client Hello
	ver, err := reader.ReadByte()
	if err != nil {
		logger.Printf("[%s] SOCKS5: Failed to read VER: %v", clientAddr, err)
		return
	}
	if ver != socks5Version {
		logger.Printf("[%s] SOCKS5: Unsupported SOCKS version %x", clientAddr, ver)
		return
	}

	nmethods, err := reader.ReadByte()
	if err != nil {
		logger.Printf("[%s] SOCKS5: Failed to read NMETHODS: %v", clientAddr, err)
		return
	}

	methods := make([]byte, nmethods)
	_, err = io.ReadFull(reader, methods)
	if err != nil {
		logger.Printf("[%s] SOCKS5: Failed to read METHODS: %v", clientAddr, err)
		return
	}

	// Server chooses authentication method (No Auth required for now)
	_, err = clientConn.Write([]byte{socks5Version, 0x00}) // 0x00 for NO AUTHENTICATION REQUIRED
	if err != nil {
		logger.Printf("[%s] SOCKS5: Failed to send method selection: %v", clientAddr, err)
		return
	}
	if cfg.VerboseLog {
		logger.Printf("[%s] SOCKS5: Sent NO AUTHENTICATION REQUIRED.", clientAddr)
	}

	// SOCKS5 Request: Client Request
	requestVer, err := reader.ReadByte()
	if err != nil {
		logger.Printf("[%s] SOCKS5: Failed to read request VER: %v", clientAddr, err)
		return
	}
	if requestVer != socks5Version {
		logger.Printf("[%s] SOCKS5: Unsupported SOCKS request version %x", clientAddr, requestVer)
		return
	}

	cmd, err := reader.ReadByte()
	if err != nil {
		logger.Printf("[%s] SOCKS5: Failed to read CMD: %v", clientAddr, err)
		return
	}
	if cmd != socks5CmdConnect {
		logger.Printf("[%s] SOCKS5: Command %x not supported. Only CONNECT (0x01) is supported.", clientAddr, cmd)
		sendSocks5Reply(clientConn, socks5ReplyCommandNotSupported, nil, 0, logger)
		return
	}

	_, err = reader.ReadByte() // discard RSV
	if err != nil {
		logger.Printf("[%s] SOCKS5: Failed to read RSV: %v", clientAddr, err)
		return
	}

	atyp, err := reader.ReadByte()
	if err != nil {
		logger.Printf("[%s] SOCKS5: Failed to read ATYP: %v", clientAddr, err)
		return
	}

	var destAddr string
	var destPort int

	switch atyp {
	case socks5ATYPIPv4:
		ip := make(net.IP, 4)
		_, err = io.ReadFull(reader, ip)
		if err != nil {
			logger.Printf("[%s] SOCKS5: Failed to read IPv4 address: %v", clientAddr, err)
			sendSocks5Reply(clientConn, socks5ReplyGeneralFailure, nil, 0, logger)
			return
		}
		destAddr = ip.String()
	case socks5ATYPDomain:
		domainLen, err := reader.ReadByte()
		if err != nil {
			logger.Printf("[%s] SOCKS5: Failed to read domain length: %v", clientAddr, err)
			sendSocks5Reply(clientConn, socks5ReplyGeneralFailure, nil, 0, logger)
			return
		}
		domain := make([]byte, domainLen)
		_, err = io.ReadFull(reader, domain)
		if err != nil {
			logger.Printf("[%s] SOCKS5: Failed to read domain name: %v", clientAddr, err)
			sendSocks5Reply(clientConn, socks5ReplyGeneralFailure, nil, 0, logger)
			return
		}
		destAddr = string(domain)
	case socks5ATYPIPv6:
		ip := make(net.IP, 16)
		_, err = io.ReadFull(reader, ip)
		if err != nil {
			logger.Printf("[%s] SOCKS5: Failed to read IPv6 address: %v", clientAddr, err)
			sendSocks5Reply(clientConn, socks5ReplyGeneralFailure, nil, 0, logger)
			return
		}
		destAddr = "[" + ip.String() + "]" // IPv6 addresses are typically enclosed in brackets
	default:
		logger.Printf("[%s] SOCKS5: Address type %x not supported.", clientAddr, atyp)
		sendSocks5Reply(clientConn, socks5ReplyAddressTypeNotSupported, nil, 0, logger)
		return
	}

	var portBytes [2]byte
	_, err = io.ReadFull(reader, portBytes[:])
	if err != nil {
		logger.Printf("[%s] SOCKS5: Failed to read port: %v", clientAddr, err)
		sendSocks5Reply(clientConn, socks5ReplyGeneralFailure, nil, 0, logger)
		return
	}
	destPort = int(portBytes[0])<<8 | int(portBytes[1])

	target := net.JoinHostPort(destAddr, fmt.Sprintf("%d", destPort))
	logger.Printf("[%s] SOCKS5: CONNECT request for target: %s", clientAddr, target)

	// Send SOCKS5 success reply
	sendSocks5Reply(clientConn, socks5ReplySuccess, nil, 0, logger)

	// Now proceed with the HTTP CONNECT tunneling
	HandleHTTPConnect(target, clientConn, cfg, logger)
}

// sendSocks5Reply sends a SOCKS5 reply to the client.
// bindAddr and bindPort are for BND.ADDR and BND.PORT, which are not used for CONNECT command success.
func sendSocks5Reply(conn net.Conn, rep byte, bindAddr net.IP, bindPort int, logger *log.Logger) {
	buf := []byte{socks5Version, rep, 0x00} // VER, REP, RSV

	// For CONNECT command, BND.ADDR and BND.PORT are typically 0.0.0.0:0
	if len(bindAddr) == 0 {
		buf = append(buf, socks5ATYPIPv4)         // ATYP: IPv4
		buf = append(buf, 0x00, 0x00, 0x00, 0x00) // BND.ADDR: 0.0.0.0
		buf = append(buf, 0x00, 0x00)             // BND.PORT: 0
	} else if len(bindAddr) == 4 {
		buf = append(buf, socks5ATYPIPv4)
		buf = append(buf, bindAddr...)
		buf = append(buf, byte(bindPort>>8), byte(bindPort&0xFF))
	} else if len(bindAddr) == 16 {
		buf = append(buf, socks5ATYPIPv6)
		buf = append(buf, bindAddr...)
		buf = append(buf, byte(bindPort>>8), byte(bindPort&0xFF))
	} else {
		// Fallback to 0.0.0.0:0 if address type is unknown/unsupported
		buf = append(buf, socks5ATYPIPv4)
		buf = append(buf, 0x00, 0x00, 0x00, 0x00)
		buf = append(buf, 0x00, 0x00)
	}

	_, err := conn.Write(buf)
	if err != nil {
		logger.Printf("SOCKS5: Failed to send reply: %v", err)
	}
}
