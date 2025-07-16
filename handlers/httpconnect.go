// FILE: handlers/httpconnect.go

package handlers

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/eWloYW8/GoProxyTunnel/config"
)

// createTLSConfig creates a *tls.Config based on provided certificate files and insecure flag.
func createTLSConfig(caCertFile, clientCertFile, clientKeyFile string, insecureSkipVerify bool, logger *log.Logger) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: insecureSkipVerify,
	}

	if caCertFile != "" {
		caCert, err := os.ReadFile(caCertFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate from %s: %w", caCertFile, err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate from %s", caCertFile)
		}
		tlsConfig.RootCAs = caCertPool
		logger.Printf("Loaded custom CA certificate from %s", caCertFile)
	}

	if clientCertFile != "" && clientKeyFile != "" {
		clientCert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate and key from %s and %s: %w", clientCertFile, clientKeyFile, err)
		}
		tlsConfig.Certificates = []tls.Certificate{clientCert}
		logger.Printf("Loaded client certificate and key from %s and %s", clientCertFile, clientKeyFile)
	} else if clientCertFile != "" || clientKeyFile != "" {
		return nil, fmt.Errorf("both client certificate and key files must be provided if one is specified")
	}

	if insecureSkipVerify {
		logger.Printf("TLS certificate verification is DISABLED (insecureSkipVerify=true).")
	}

	return tlsConfig, nil
}

// dialWithRetries attempts to establish a connection with retries and a timeout.
func dialWithRetries(network, addr string, tlsConfig *tls.Config, cfg *config.Config, logger *log.Logger, clientAddr net.Addr) (net.Conn, error) {
	var conn net.Conn
	var err error

	for i := 0; i <= cfg.MaxRetries; i++ {
		if i > 0 {
			logger.Printf("[%s] Retrying connection to %s://%s (attempt %d/%d) after %v...", clientAddr, network, addr, i, cfg.MaxRetries, cfg.RetryDelay)
			time.Sleep(cfg.RetryDelay)
		}

		if network == "https" {
			// For TLS connections, tls.Dial has its own connect timeout mechanism if no deadline is set on the underlying conn.
			// However, for consistency and to respect cfg.ConnectTimeout, we'll pass it to the dialer.
			dialer := &net.Dialer{Timeout: cfg.ConnectTimeout}
			conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
		} else { // http (plain tcp)
			conn, err = net.DialTimeout("tcp", addr, cfg.ConnectTimeout)
		}

		if err == nil {
			return conn, nil
		}

		logger.Printf("[%s] Failed to connect to %s://%s: %v", clientAddr, network, addr, err)
		if i == cfg.MaxRetries {
			return nil, fmt.Errorf("failed to connect to %s://%s after %d retries: %w", network, addr, cfg.MaxRetries, err)
		}
	}
	return nil, fmt.Errorf("unexpected error in dialWithRetries: connection loop finished without returning")
}

// HandleHTTPConnect manages a client connection and tunnels it through an HTTP CONNECT proxy.
func HandleHTTPConnect(target string, clientConn net.Conn, cfg *config.Config, logger *log.Logger) {
	defer clientConn.Close()
	clientAddr := clientConn.RemoteAddr()

	logger.Printf("Accepted connection from %s", clientAddr)

	if cfg.ReadWriteTimeout > 0 {
		clientConn.SetReadDeadline(time.Now().Add(cfg.ReadWriteTimeout))
		clientConn.SetWriteDeadline(time.Now().Add(cfg.ReadWriteTimeout))
	}

	var proxyConn net.Conn
	var err error

	// Establish connection to proxy with retries
	if cfg.ProxyScheme == "https" {
		proxyTLSConfig, err := createTLSConfig(cfg.ProxyCACertFile, cfg.ProxyClientCertFile, cfg.ProxyClientKeyFile, cfg.InsecureProxyTLS, logger)
		if err != nil {
			logger.Printf("[%s] Failed to create proxy TLS config: %v", clientAddr, err)
			return
		}
		proxyConn, err = dialWithRetries("https", cfg.ProxyAddr, proxyTLSConfig, cfg, logger, clientAddr)
	} else if cfg.ProxyScheme == "http" {
		proxyConn, err = dialWithRetries("http", cfg.ProxyAddr, nil, cfg, logger, clientAddr)
	} else {
		logger.Printf("[%s] Unsupported proxy scheme: %s. Must be 'http' or 'https'.", clientAddr, cfg.ProxyScheme)
		return
	}

	if err != nil {
		logger.Printf("[%s] Aborting connection due to proxy connection failure: %v", clientAddr, err)
		return
	}
	defer proxyConn.Close()

	// Apply read/write timeouts to the proxy connection
	if cfg.ReadWriteTimeout > 0 {
		proxyConn.SetReadDeadline(time.Now().Add(cfg.ReadWriteTimeout))
		proxyConn.SetWriteDeadline(time.Now().Add(cfg.ReadWriteTimeout))
	}

	targetHostForConnect, _, _ := net.SplitHostPort(target)

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	for k, v := range cfg.CustomHeaders {
		connectReq += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	connectReq += "\r\n"

	if cfg.VerboseLog {
		logger.Printf("[%s] Sending CONNECT request to proxy for %s:\n%s", clientAddr, target, connectReq)
	}

	_, err = proxyConn.Write([]byte(connectReq))
	if err != nil {
		logger.Printf("[%s] Failed to send CONNECT request to proxy for %s: %v", clientAddr, target, err)
		return
	}

	reader := bufio.NewReader(proxyConn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		logger.Printf("[%s] Failed to read proxy response for %s: %v", clientAddr, target, err)
		return
	}

	if cfg.VerboseLog {
		logger.Printf("[%s] Received proxy status for %s: %s", clientAddr, target, statusLine)
	}

	if !strings.Contains(statusLine, "200") {
		logger.Printf("[%s] CONNECT request for %s rejected by proxy: %s", clientAddr, target, strings.TrimSpace(statusLine))
		return
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}
		if cfg.VerboseLog {
			logger.Printf("[%s] Discarded proxy header for %s: %s", clientAddr, target, strings.TrimSpace(line))
		}
	}

	var targetConn net.Conn = proxyConn // Initially, the target connection is the proxy connection
	if cfg.UseTLSOnTarget {
		targetTLSConfig, err := createTLSConfig(cfg.TargetCACertFile, cfg.TargetClientCertFile, cfg.TargetClientKeyFile, cfg.InsecureTargetTLS, logger)
		if err != nil {
			logger.Printf("[%s] Failed to create target TLS config: %v", clientAddr, err)
			return
		}
		targetTLSConfig.ServerName = targetHostForConnect // crucial for target TLS
		tlsConn := tls.Client(proxyConn, targetTLSConfig)

		// Set handshake timeout for target TLS
		if cfg.ConnectTimeout > 0 {
			tlsConn.SetReadDeadline(time.Now().Add(cfg.ConnectTimeout))
			tlsConn.SetWriteDeadline(time.Now().Add(cfg.ConnectTimeout))
		}

		err = tlsConn.Handshake()
		// Clear deadlines after handshake so read/write timeout applies for subsequent operations
		if cfg.ConnectTimeout > 0 {
			tlsConn.SetReadDeadline(time.Time{})
			tlsConn.SetWriteDeadline(time.Time{})
		}

		if err != nil {
			logger.Printf("[%s] Target TLS handshake failed for %s: %v", clientAddr, target, err)
			return
		}
		targetConn = tlsConn
		logger.Printf("[%s] Established TLS connection to target %s", clientAddr, target)
	} else {
		logger.Printf("[%s] Established plain TCP connection to target %s", clientAddr, target)
	}

	// Apply read/write timeouts to the target connection as well (if it's distinct from proxyConn or after handshake)
	if cfg.ReadWriteTimeout > 0 {
		targetConn.SetReadDeadline(time.Now().Add(cfg.ReadWriteTimeout))
		targetConn.SetWriteDeadline(time.Now().Add(cfg.ReadWriteTimeout))
	}

	logger.Printf("Connection established: %s <--> %s (via %s proxy %s)", clientAddr, target, cfg.ProxyScheme, cfg.ProxyAddr)

	done := make(chan struct{})
	go func() {
		// io.Copy handles the data transfer. We'll rely on SetReadDeadline/SetWriteDeadline for timeouts.
		_, err := io.Copy(targetConn, clientConn)
		if err != nil {
			logger.Printf("[%s] Error copying from client to target %s: %v", clientAddr, target, err)
		}
		// Attempt to unblock the other io.Copy by setting a short deadline if an error occurs
		if cfg.ReadWriteTimeout > 0 {
			clientConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		}
		close(done)
	}()

	_, err = io.Copy(clientConn, targetConn)
	if err != nil {
		logger.Printf("[%s] Error copying from target %s to client: %v", clientAddr, target, err)
	}
	// Attempt to unblock the other io.Copy by setting a short deadline if an error occurs
	if cfg.ReadWriteTimeout > 0 {
		targetConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	}

	<-done

	logger.Printf("Connection closed: %s <--> %s", clientAddr, target)
}
