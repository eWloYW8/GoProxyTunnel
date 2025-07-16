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

// HandleHTTPConnect manages a client connection and tunnels it through an HTTP CONNECT proxy.
func HandleHTTPConnect(target string, clientConn net.Conn, cfg *config.Config, logger *log.Logger) {
	defer clientConn.Close()
	clientAddr := clientConn.RemoteAddr()

	logger.Printf("Accepted connection from %s", clientAddr)

	var proxyConn net.Conn
	var err error

	if cfg.ProxyScheme == "https" {
		proxyTLSConfig, err := createTLSConfig(cfg.ProxyCACertFile, cfg.ProxyClientCertFile, cfg.ProxyClientKeyFile, cfg.InsecureProxyTLS, logger)
		if err != nil {
			logger.Printf("[%s] Failed to create proxy TLS config: %v", clientAddr, err)
			return
		}
		proxyConn, err = tls.Dial("tcp", cfg.ProxyAddr, proxyTLSConfig)
		if err != nil {
			logger.Printf("[%s] Failed to connect to HTTPS proxy %s: %v", clientAddr, cfg.ProxyAddr, err)
			return
		}
	} else if cfg.ProxyScheme == "http" {
		proxyConn, err = net.Dial("tcp", cfg.ProxyAddr)
		if err != nil {
			logger.Printf("[%s] Failed to connect to HTTP proxy %s: %v", clientAddr, cfg.ProxyAddr, err)
			return
		}
	} else {
		logger.Printf("[%s] Unsupported proxy scheme: %s. Must be 'http' or 'https'.", clientAddr, cfg.ProxyScheme)
		return
	}
	defer proxyConn.Close()

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

	var targetConn net.Conn = proxyConn
	if cfg.UseTLSOnTarget {
		targetTLSConfig, err := createTLSConfig(cfg.TargetCACertFile, cfg.TargetClientCertFile, cfg.TargetClientKeyFile, cfg.InsecureTargetTLS, logger)
		if err != nil {
			logger.Printf("[%s] Failed to create target TLS config: %v", clientAddr, err)
			return
		}
		targetTLSConfig.ServerName = targetHostForConnect // crucial for target TLS
		tlsConn := tls.Client(proxyConn, targetTLSConfig)
		err = tlsConn.Handshake()
		if err != nil {
			logger.Printf("[%s] Target TLS handshake failed for %s: %v", clientAddr, target, err)
			return
		}
		targetConn = tlsConn
		logger.Printf("[%s] Established TLS connection to target %s", clientAddr, target)
	} else {
		logger.Printf("[%s] Established plain TCP connection to target %s", clientAddr, target)
	}

	logger.Printf("Connection established: %s <--> %s (via %s proxy %s)", clientAddr, target, cfg.ProxyScheme, cfg.ProxyAddr)

	done := make(chan struct{})
	go func() {
		_, err := io.Copy(targetConn, clientConn)
		if err != nil {
			logger.Printf("[%s] Error copying from client to target %s: %v", clientAddr, target, err)
		}
		targetConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		close(done)
	}()

	_, err = io.Copy(clientConn, targetConn)
	if err != nil {
		logger.Printf("[%s] Error copying from target %s to client: %v", clientAddr, target, err)
	}
	clientConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

	<-done

	logger.Printf("Connection closed: %s <--> %s", clientAddr, target)
}
