package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/eWloYW8/GoProxyTunnel/config"
	"github.com/eWloYW8/GoProxyTunnel/handlers"
	"github.com/eWloYW8/GoProxyTunnel/util"
)

var logger *log.Logger

var Version = "dev-build"

func init() {
	logger = log.New(os.Stderr, "", log.LstdFlags|log.Lmicroseconds)
}

func main() {
	cfg := config.ParseFlags()

	var workerConfigs []*config.Config
	if cfg.ConfigFile != "" {
		loadedConfigs, err := config.LoadConfigFromYAML(cfg.ConfigFile, logger)
		if err != nil {
			logger.Fatalf("Error loading configuration from %s: %v", cfg.ConfigFile, err)
		}
		workerConfigs = loadedConfigs
		logger.Printf("Loaded %d worker configurations from %s", len(workerConfigs), cfg.ConfigFile)
	} else {
		workerConfigs = []*config.Config{cfg}
	}

	if cfg.UseStdio && !cfg.SilentLog {
		cfg.SilentLog = true
	}

	if cfg.SilentLog {
		logger.SetOutput(io.Discard)
	}

	fmt.Fprintf(os.Stderr, "GoProxyTunnel %s - A TCP proxy tunnel over HTTP CONNECT in Go.\n", Version)

	var wg sync.WaitGroup

	for i, workerCfg := range workerConfigs {
		workerCfg.VerboseLog = cfg.VerboseLog
		if cfg.SilentLog {
			logger.SetOutput(io.Discard)
		} else {
			logger.SetOutput(os.Stderr)
		}

		missingFlags := []string{}
		if workerCfg.ProxyAddrStr == "" {
			missingFlags = append(missingFlags, "proxy")
		}

		if workerCfg.UseSocks5Proxy && workerCfg.TargetAddrStr != "" {
			logger.Fatalf("Error (Worker %d): Cannot use -socks5 and -target together. In SOCKS5 mode, the target is determined by the client.", i+1)
		}

		if !workerCfg.UseSocks5Proxy && workerCfg.TargetAddrStr == "" {
			missingFlags = append(missingFlags, "target")
		}

		if workerCfg.UseStdio && workerCfg.LocalListenAddrStr != "" {
			logger.Fatalf("Error (Worker %d): Cannot use -stdio and -listen together. Choose one mode of operation.", i+1)
		}

		if !workerCfg.UseStdio && workerCfg.LocalListenAddrStr == "" {
			missingFlags = append(missingFlags, "listen or stdio")
		}

		if len(missingFlags) > 0 {
			logger.Printf("Missing required arguments for Worker %d: %s.\nUse -h for help.", i+1, strings.Join(missingFlags, ", "))
			config.PrintUsage()
			os.Exit(1)
		}

		var err error
		if !workerCfg.UseStdio {
			workerCfg.LocalListenAddr, err = net.ResolveTCPAddr("tcp", workerCfg.LocalListenAddrStr)
			if err != nil {
				logger.Fatalf("Invalid listen address '%s' for Worker %d: %v", workerCfg.LocalListenAddrStr, i+1, err)
			}
		}

		proxyHost, proxyPort, err := net.SplitHostPort(workerCfg.ProxyAddrStr)
		if err != nil {
			logger.Fatalf("Invalid proxy address '%s' for Worker %d: %v. Expected 'host:port'.", workerCfg.ProxyAddrStr, i+1, err)
		}
		workerCfg.ProxyAddr = net.JoinHostPort(proxyHost, proxyPort)

		if !workerCfg.UseSocks5Proxy {
			targetHost, targetPort, err := net.SplitHostPort(workerCfg.TargetAddrStr)
			if err != nil {
				logger.Fatalf("Invalid target address '%s' for Worker %d: %v. Expected 'host:port'.", workerCfg.TargetAddrStr, i+1, err)
			}
			workerCfg.TargetAddr = net.JoinHostPort(targetHost, targetPort)
		}

		if workerCfg.VerboseLog {
			logger.Printf("Worker %d: Verbose logging enabled.", i+1)
		}

		workerCfg.CustomHeaders = make(map[string]string)
		if workerCfg.CustomHeadersStr != "" {
			headers := strings.Split(workerCfg.CustomHeadersStr, ",")
			for _, header := range headers {
				parts := strings.SplitN(header, ":", 2)
				if len(parts) == 2 {
					workerCfg.CustomHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
				} else {
					logger.Printf("Warning (Worker %d): Malformed custom header ignored: '%s'. Expected 'Key:Value'.", i+1, header)
				}
			}
		}

		if workerCfg.AuthorizationCreds != "" {
			workerCfg.CustomHeaders["Proxy-Authorization"] = "Basic " + util.EncodeBase64(workerCfg.AuthorizationCreds)
			logger.Printf("Worker %d: Authorization credentials provided and automatically encoded.", i+1)
		}

		wg.Add(1)
		go func(cfg *config.Config, workerID int) {
			defer wg.Done()
			runWorker(cfg, workerID)
		}(workerCfg, i+1)
	}

	wg.Wait()
	logger.Println("All GoProxyTunnel workers have stopped.")
}

func runWorker(cfg *config.Config, workerID int) {
	if cfg.UseStdio {
		logger.Printf("Worker %d: Using stdin/stdout for communication, proxying via %s://%s to %s. Target TLS: %t",
			workerID, cfg.ProxyScheme, cfg.ProxyAddr, cfg.TargetAddr, cfg.UseTLSOnTarget)
		handlers.HandleHTTPConnect(cfg.TargetAddr, &util.StdioConn{Logger: logger}, cfg, logger)
	} else {
		listener, err := net.Listen("tcp", cfg.LocalListenAddr.String())
		if err != nil {
			logger.Fatalf("Worker %d: Failed to listen on %s: %v", workerID, cfg.LocalListenAddr.String(), err)
		}
		defer listener.Close()

		if cfg.UseSocks5Proxy {
			logger.Printf("Worker %d: Listening on %s as SOCKS5 proxy, tunneling via %s://%s.",
				workerID, cfg.LocalListenAddr.String(), cfg.ProxyScheme, cfg.ProxyAddr)
			for {
				conn, err := listener.Accept()
				if err != nil {
					logger.Printf("Worker %d: Failed to accept connection: %v", workerID, err)
					continue
				}
				go handlers.HandleSocks5(conn, cfg, logger)
			}
		} else {
			logger.Printf("Worker %d: Listening on %s, proxying via %s://%s to %s. Target TLS: %t",
				workerID, cfg.LocalListenAddr.String(), cfg.ProxyScheme, cfg.ProxyAddr, cfg.TargetAddr, cfg.UseTLSOnTarget)
			for {
				conn, err := listener.Accept()
				if err != nil {
					logger.Printf("Worker %d: Failed to accept connection: %v", workerID, err)
					continue
				}
				go handlers.HandleHTTPConnect(cfg.TargetAddr, conn, cfg, logger)
			}
		}
	}
}
