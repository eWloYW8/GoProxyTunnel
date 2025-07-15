package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"

	"github.com/eWloYW8/GoProxyTunnel/config"
	"github.com/eWloYW8/GoProxyTunnel/handlers"
	"github.com/eWloYW8/GoProxyTunnel/util"
)

var logger *log.Logger

func init() {
	logger = log.New(os.Stderr, "", log.LstdFlags|log.Lmicroseconds)
}

func main() {
	cfg := config.ParseFlags()

	if cfg.UseStdio && !cfg.SilentLog {
		cfg.SilentLog = true
	}

	if cfg.SilentLog {
		logger.SetOutput(io.Discard)
	}

	missingFlags := []string{}
	if cfg.ProxyAddrStr == "" {
		missingFlags = append(missingFlags, "proxy")
	}

	if cfg.UseSocks5Proxy && cfg.TargetAddrStr != "" {
		logger.Fatalf("Error: Cannot use -socks5 and -target together. In SOCKS5 mode, the target is determined by the client.")
	}

	if !cfg.UseSocks5Proxy && cfg.TargetAddrStr == "" {
		missingFlags = append(missingFlags, "target")
	}

	fmt.Fprintln(os.Stderr, "GoProxyTunnel - A TCP proxy tunnel over HTTP CONNECT in Go.")

	if cfg.UseStdio && cfg.LocalListenAddrStr != "" {
		logger.Fatalf("Error: Cannot use -stdio and -listen together. Choose one mode of operation.")
	}

	if !cfg.UseStdio && cfg.LocalListenAddrStr == "" {
		missingFlags = append(missingFlags, "listen or stdio")
	}

	if len(missingFlags) > 0 {
		logger.Printf("Missing required arguments: %s.\nUse -h for help.", strings.Join(missingFlags, ", "))
		config.PrintUsage()
		os.Exit(1)
	}

	var err error

	if !cfg.UseStdio {
		cfg.LocalListenAddr, err = net.ResolveTCPAddr("tcp", cfg.LocalListenAddrStr)
		if err != nil {
			logger.Fatalf("Invalid listen address '%s': %v", cfg.LocalListenAddrStr, err)
		}
	}

	proxyHost, proxyPort, err := net.SplitHostPort(cfg.ProxyAddrStr)
	if err != nil {
		logger.Fatalf("Invalid proxy address '%s': %v. Expected 'host:port'.", cfg.ProxyAddrStr, err)
	}
	cfg.ProxyAddr = net.JoinHostPort(proxyHost, proxyPort)

	if !cfg.UseSocks5Proxy {
		targetHost, targetPort, err := net.SplitHostPort(cfg.TargetAddrStr)
		if err != nil {
			logger.Fatalf("Invalid target address '%s': %v. Expected 'host:port'.", cfg.TargetAddrStr, err)
		}
		cfg.TargetAddr = net.JoinHostPort(targetHost, targetPort)
	}

	if cfg.VerboseLog {
		logger.Printf("Verbose logging enabled.")
	}

	cfg.CustomHeaders = make(map[string]string)
	if cfg.CustomHeadersStr != "" {
		headers := strings.Split(cfg.CustomHeadersStr, ",")
		for _, header := range headers {
			parts := strings.SplitN(header, ":", 2)
			if len(parts) == 2 {
				cfg.CustomHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			} else {
				logger.Printf("Warning: Malformed custom header ignored: '%s'. Expected 'Key:Value'.", header)
			}
		}
	}

	if cfg.AuthorizationCreds != "" {
		cfg.CustomHeaders["Proxy-Authorization"] = "Basic " + util.EncodeBase64(cfg.AuthorizationCreds)
		logger.Printf("Authorization credentials provided and automatically encoded.")
	}

	if cfg.UseStdio {
		logger.Printf("Using stdin/stdout for communication, proxying via %s://%s to %s. Target TLS: %t",
			cfg.ProxyScheme, cfg.ProxyAddr, cfg.TargetAddr, cfg.UseTLSOnTarget)
		handlers.HandleHTTPConnect(cfg.TargetAddr, &util.StdioConn{Logger: logger}, cfg, logger)
	} else {
		listener, err := net.Listen("tcp", cfg.LocalListenAddr.String())
		if err != nil {
			logger.Fatalf("Failed to listen on %s: %v", cfg.LocalListenAddr.String(), err)
		}

		if cfg.UseSocks5Proxy {
			logger.Printf("Listening on %s as SOCKS5 proxy, tunneling via %s://%s.",
				cfg.LocalListenAddr.String(), cfg.ProxyScheme, cfg.ProxyAddr)
			for {
				conn, err := listener.Accept()
				if err != nil {
					logger.Printf("Failed to accept connection: %v", err)
					continue
				}
				go handlers.HandleSocks5(conn, cfg, logger)
			}
		} else {
			logger.Printf("Listening on %s, proxying via %s://%s to %s. Target TLS: %t",
				cfg.LocalListenAddr.String(), cfg.ProxyScheme, cfg.ProxyAddr, cfg.TargetAddr, cfg.UseTLSOnTarget)
			for {
				conn, err := listener.Accept()
				if err != nil {
					logger.Printf("Failed to accept connection: %v", err)
					continue
				}
				go handlers.HandleHTTPConnect(cfg.TargetAddr, conn, cfg, logger)
			}
		}
	}
}
