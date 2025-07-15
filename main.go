package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

var (
	localListenAddrStr string
	proxyScheme        string
	proxyAddrStr       string
	targetAddrStr      string
	useTLSOnTarget     bool
	customHeadersStr   string
	authorizationCreds string
	verboseLog         bool
	useStdio           bool
	silentLog          bool

	localListenAddr *net.TCPAddr
	proxyAddr       string
	targetAddr      string
	customHeaders   map[string]string

	logger *log.Logger
)

func init() {
	flag.StringVar(&localListenAddrStr, "listen", "", "Local address and port to listen on (e.g., 127.0.0.1:25000). Required unless -stdio is used.")
	flag.StringVar(&proxyScheme, "proxy-scheme", "https", "Proxy scheme (http or https)")
	flag.StringVar(&proxyAddrStr, "proxy", "", "REQUIRED: Proxy server address (e.g., proxy.example.com:8443)")
	flag.StringVar(&targetAddrStr, "target", "", "REQUIRED: Target server address (e.g., 192.168.1.100:8080)")
	flag.BoolVar(&useTLSOnTarget, "target-tls", false, "Whether to use TLS on the target connection")
	flag.StringVar(&customHeadersStr, "headers", "", "Comma-separated custom request headers (e.g., \"User-Agent:GoProxy,X-Forwarded-For:1.2.3.4\")")
	flag.StringVar(&authorizationCreds, "auth-creds", "", "Proxy-Authorization credentials (format: \"username:password\"). Will be Base64 encoded automatically.")
	flag.BoolVar(&verboseLog, "verbose", false, "Enable verbose logging")
	flag.BoolVar(&useStdio, "stdio", false, "Use stdin/stdout for communication instead of listening on a network address. Conflicts with -listen. Recommend using -silent with this flag to suppress logging.")
	flag.BoolVar(&silentLog, "silent", false, "Disable all logging output to stderr.")

	flag.Usage = func() {
		requiredFlagsOrder := []string{
			"proxy",
			"target",
		}

		optionalFlagsOrder := []string{
			"listen",
			"stdio",
			"proxy-scheme",
			"target-tls",
			"auth-creds",
			"headers",
			"verbose",
			"silent",
		}

		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  ConnectForwarder -proxy proxy.example.com:8443 -target 192.168.1.100:8080 -listen 127.0.0.1:25000")
		fmt.Fprintln(os.Stderr, "  ConnectForwarder -proxy proxy.example.com:8443 -target 192.168.1.100:8080 -stdio")

		allFlags := make(map[string]*flag.Flag)
		flag.VisitAll(func(f *flag.Flag) {
			allFlags[f.Name] = f
		})

		fmt.Fprintln(os.Stderr, "  Required Parameters (always):")
		for _, name := range requiredFlagsOrder {
			if f, ok := allFlags[name]; ok {
				fmt.Fprintf(os.Stderr, "    -%s %s\n        %s\n", f.Name, f.DefValue, f.Usage)
				delete(allFlags, name)
			}
		}

		fmt.Fprintln(os.Stderr, "\n  Connection Mode Parameters (choose one):")
		if f, ok := allFlags["listen"]; ok {
			fmt.Fprintf(os.Stderr, "    -%s %s\n        %s\n", f.Name, f.DefValue, f.Usage)
			delete(allFlags, "listen")
		}
		if f, ok := allFlags["stdio"]; ok {
			fmt.Fprintf(os.Stderr, "    -%s %s\n        %s\n", f.Name, f.DefValue, f.Usage)
			delete(allFlags, "stdio")
		}

		fmt.Fprintln(os.Stderr, "\n  Optional Parameters:")
		for _, name := range optionalFlagsOrder {
			if _, ok := allFlags[name]; ok {
				f := allFlags[name]
				fmt.Fprintf(os.Stderr, "    -%s %s\n        %s\n", f.Name, f.DefValue, f.Usage)
				delete(allFlags, name)
			}
		}

		if len(allFlags) > 0 {
			fmt.Fprintln(os.Stderr, "\n  Other Parameters (alphabetical):")
			flag.PrintDefaults()
		}
	}

	logger = log.New(os.Stderr, "", log.LstdFlags|log.Lmicroseconds)
}

func main() {
	flag.Parse()

	if useStdio && !silentLog {
		silentLog = true
	}

	if silentLog {
		logger.SetOutput(io.Discard)
	}

	missingFlags := []string{}
	if proxyAddrStr == "" {
		missingFlags = append(missingFlags, "proxy")
	}
	if targetAddrStr == "" {
		missingFlags = append(missingFlags, "target")
	}

	fmt.Fprintln(os.Stderr, "GoProxyTunnel - A TCP proxy tunnel over HTTP CONNECT in Go.")

	if useStdio && localListenAddrStr != "" {
		logger.Fatalf("Error: Cannot use -stdio and -listen together. Choose one mode of operation.")
	}

	if !useStdio && localListenAddrStr == "" {
		missingFlags = append(missingFlags, "listen or stdio")
	}

	if len(missingFlags) > 0 {
		logger.Printf("Missing required arguments: %s.\nUse -h for help.", strings.Join(missingFlags, ", "))
		flag.Usage()
		os.Exit(1)
	}

	var err error

	if !useStdio {
		localListenAddr, err = net.ResolveTCPAddr("tcp", localListenAddrStr)
		if err != nil {
			logger.Fatalf("Invalid listen address '%s': %v", localListenAddrStr, err)
		}
	}

	proxyHost, proxyPort, err := net.SplitHostPort(proxyAddrStr)
	if err != nil {
		logger.Fatalf("Invalid proxy address '%s': %v. Expected 'host:port'.", proxyAddrStr, err)
	}
	proxyAddr = net.JoinHostPort(proxyHost, proxyPort)

	targetHost, targetPort, err := net.SplitHostPort(targetAddrStr)
	if err != nil {
		logger.Fatalf("Invalid target address '%s': %v. Expected 'host:port'.", targetAddrStr, err)
	}
	targetAddr = net.JoinHostPort(targetHost, targetPort)

	if verboseLog {
		logger.Printf("Verbose logging enabled.")
	}

	customHeaders = make(map[string]string)
	if customHeadersStr != "" {
		headers := strings.Split(customHeadersStr, ",")
		for _, header := range headers {
			parts := strings.SplitN(header, ":", 2)
			if len(parts) == 2 {
				customHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			} else {
				logger.Printf("Warning: Malformed custom header ignored: '%s'. Expected 'Key:Value'.", header)
			}
		}
	}

	if authorizationCreds != "" {
		encodedAuth := base64.StdEncoding.EncodeToString([]byte(authorizationCreds))
		customHeaders["Proxy-Authorization"] = "Basic " + encodedAuth
		logger.Printf("Authorization credentials provided and automatically encoded.")
	}

	if useStdio {
		logger.Printf("Using stdin/stdout for communication, proxying via %s://%s to %s. Target TLS: %t",
			proxyScheme, proxyAddr, targetAddr, useTLSOnTarget)
		handleConn(&stdioConn{logger: logger})
	} else {
		listener, err := net.Listen("tcp", localListenAddr.String())
		if err != nil {
			logger.Fatalf("Failed to listen on %s: %v", localListenAddr.String(), err)
		}
		logger.Printf("Listening on %s, proxying via %s://%s to %s. Target TLS: %t",
			localListenAddr.String(), proxyScheme, proxyAddr, targetAddr, useTLSOnTarget)

		for {
			conn, err := listener.Accept()
			if err != nil {
				logger.Printf("Failed to accept connection: %v", err)
				continue
			}
			go handleConn(conn)
		}
	}
}

type stdioConn struct {
	logger *log.Logger
}

func (s *stdioConn) Read(b []byte) (n int, err error) {
	if s.logger.Writer() != io.Discard {
		s.logger.Printf("[STDIO] Reading from stdin...")
	}
	n, err = os.Stdin.Read(b)
	if err != nil {
		if s.logger.Writer() != io.Discard {
			if err == io.EOF {
				s.logger.Printf("[STDIO] EOF on stdin.")
			} else {
				s.logger.Printf("[STDIO] Error reading from stdin: %v", err)
			}
		}
	}
	return n, err
}

func (s *stdioConn) Write(b []byte) (n int, err error) {
	if s.logger.Writer() != io.Discard {
		s.logger.Printf("[STDIO] Writing to stdout...")
	}
	n, err = os.Stdout.Write(b)
	if err != nil {
		if s.logger.Writer() != io.Discard {
			s.logger.Printf("[STDIO] Error writing to stdout: %v", err)
		}
	}
	return n, err
}

func (s *stdioConn) Close() error {
	if s.logger.Writer() != io.Discard {
		s.logger.Printf("[STDIO] Closing stdin/stdout connection.")
	}
	return nil
}

func (s *stdioConn) LocalAddr() net.Addr {
	return &net.IPAddr{IP: net.ParseIP("127.0.0.1")}
}

func (s *stdioConn) RemoteAddr() net.Addr {
	return &net.IPAddr{IP: net.ParseIP("127.0.0.1")}
}

func (s *stdioConn) SetDeadline(t time.Time) error {
	return nil
}

func (s *stdioConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (s *stdioConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func handleConn(clientConn net.Conn) {
	defer clientConn.Close()
	clientAddr := clientConn.RemoteAddr()

	logger.Printf("Accepted connection from %s", clientAddr)

	var proxyConn net.Conn
	var err error

	if proxyScheme == "https" {
		proxyConn, err = tls.Dial("tcp", proxyAddr, nil)
		if err != nil {
			logger.Printf("[%s] Failed to connect to HTTPS proxy %s: %v", clientAddr, proxyAddr, err)
			return
		}
	} else if proxyScheme == "http" {
		proxyConn, err = net.Dial("tcp", proxyAddr)
		if err != nil {
			logger.Printf("[%s] Failed to connect to HTTP proxy %s: %v", clientAddr, proxyAddr, err)
			return
		}
	} else {
		logger.Printf("[%s] Unsupported proxy scheme: %s. Must be 'http' or 'https'.", clientAddr, proxyScheme)
		return
	}
	defer proxyConn.Close()

	targetHostForConnect, _, _ := net.SplitHostPort(targetAddr)

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetAddr, targetAddr)
	for k, v := range customHeaders {
		connectReq += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	connectReq += "\r\n"

	if verboseLog {
		logger.Printf("[%s] Sending CONNECT request to proxy:\n%s", clientAddr, connectReq)
	}

	_, err = proxyConn.Write([]byte(connectReq))
	if err != nil {
		logger.Printf("[%s] Failed to send CONNECT request to proxy: %v", clientAddr, err)
		return
	}

	reader := bufio.NewReader(proxyConn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		logger.Printf("[%s] Failed to read proxy response: %v", clientAddr, err)
		return
	}

	if verboseLog {
		logger.Printf("[%s] Received proxy status: %s", clientAddr, statusLine)
	}

	if !strings.Contains(statusLine, "200") {
		logger.Printf("[%s] CONNECT request rejected by proxy: %s", clientAddr, strings.TrimSpace(statusLine))
		return
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}
		if verboseLog {
			logger.Printf("[%s] Discarded proxy header: %s", clientAddr, strings.TrimSpace(line))
		}
	}

	var targetConn net.Conn = proxyConn
	if useTLSOnTarget {
		tlsConn := tls.Client(proxyConn, &tls.Config{
			ServerName:         targetHostForConnect,
			InsecureSkipVerify: true,
		})
		err = tlsConn.Handshake()
		if err != nil {
			logger.Printf("[%s] Target TLS handshake failed: %v", clientAddr, err)
			return
		}
		targetConn = tlsConn
		logger.Printf("[%s] Established TLS connection to target %s", clientAddr, targetAddr)
	} else {
		logger.Printf("[%s] Established plain TCP connection to target %s", clientAddr, targetAddr)
	}

	logger.Printf("Connection established: %s <--> %s (via %s proxy %s)", clientAddr, targetAddr, proxyScheme, proxyAddr)

	done := make(chan struct{})
	go func() {
		_, err := io.Copy(targetConn, clientConn)
		if err != nil {
			logger.Printf("[%s] Error copying from client to target: %v", clientAddr, err)
		}
		targetConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		close(done)
	}()

	_, err = io.Copy(clientConn, targetConn)
	if err != nil {
		logger.Printf("[%s] Error copying from target to client: %v", clientAddr, err)
	}
	clientConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

	<-done

	logger.Printf("Connection closed: %s <--> %s", clientAddr, targetAddr)
}
