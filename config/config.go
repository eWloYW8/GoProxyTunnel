// FILE: config/config.go

package config

import (
	"encoding/base64"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"
)

// Config holds all the application's configuration parameters.
type Config struct {
	LocalListenAddrStr string
	ProxyScheme        string
	ProxyAddrStr       string
	TargetAddrStr      string // unused in SOCKS5 mode
	UseTLSOnTarget     bool
	CustomHeadersStr   string
	AuthorizationCreds string
	VerboseLog         bool
	UseStdio           bool
	SilentLog          bool
	UseSocks5Proxy     bool

	ProxyCACertFile      string
	ProxyClientCertFile  string
	ProxyClientKeyFile   string
	TargetCACertFile     string
	TargetClientCertFile string
	TargetClientKeyFile  string
	InsecureProxyTLS     bool
	InsecureTargetTLS    bool

	ConnectTimeout   time.Duration // Timeout for establishing a new connection
	ReadWriteTimeout time.Duration // Timeout for read/write operations on established connections
	MaxRetries       int           // Maximum number of connection retries
	RetryDelay       time.Duration // Delay between retry attempts

	LocalListenAddr *net.TCPAddr
	ProxyAddr       string
	TargetAddr      string // This will be set dynamically per SOCKS5 request
	CustomHeaders   map[string]string
}

// ParseFlags parses the command-line arguments and returns a Config struct.
func ParseFlags() *Config {
	cfg := &Config{}

	flag.StringVar(&cfg.LocalListenAddrStr, "listen", "", "Local address and port to listen on (e.g., 127.0.0.1:25000). Required unless -stdio is used.")
	flag.StringVar(&cfg.ProxyScheme, "proxy-scheme", "https", "Proxy scheme (http or https)")
	flag.StringVar(&cfg.ProxyAddrStr, "proxy", "", "REQUIRED: Proxy server address (e.g., proxy.example.com:8443)")
	flag.StringVar(&cfg.TargetAddrStr, "target", "", "Target server address (e.g., 192.168.1.100:8080). Required unless -socks5 is used.")
	flag.BoolVar(&cfg.UseTLSOnTarget, "target-tls", false, "Whether to use TLS on the target connection")
	flag.StringVar(&cfg.CustomHeadersStr, "headers", "", "Comma-separated custom request headers (e.g., \"User-Agent:GoProxy,X-Forwarded-For:1.2.3.4\")")
	flag.StringVar(&cfg.AuthorizationCreds, "auth-creds", "", "Proxy-Authorization credentials (format: \"username:password\"). Will be Base64 encoded automatically.")
	flag.BoolVar(&cfg.VerboseLog, "verbose", false, "Enable verbose logging")
	flag.BoolVar(&cfg.UseStdio, "stdio", false, "Use stdin/stdout for communication instead of listening on a network address. Conflicts with -listen. Recommend using -silent with this flag to suppress logging.")
	flag.BoolVar(&cfg.SilentLog, "silent", false, "Disable all logging output to stderr.")
	flag.BoolVar(&cfg.UseSocks5Proxy, "socks5", false, "Enable SOCKS5 proxy mode. When enabled, -target is not used, and the listen port acts as a SOCKS5 server. (UDP is not supported.)")

	// TLS flags
	flag.StringVar(&cfg.ProxyCACertFile, "proxy-ca-cert", "", "Path to a custom CA certificate file for the proxy (PEM format).")
	flag.StringVar(&cfg.ProxyClientCertFile, "proxy-client-cert", "", "Path to a client certificate file for proxy mutual TLS (PEM format).")
	flag.StringVar(&cfg.ProxyClientKeyFile, "proxy-client-key", "", "Path to a client private key file for proxy mutual TLS (PEM format).")
	flag.BoolVar(&cfg.InsecureProxyTLS, "insecure-proxy-tls", false, "Disable TLS certificate verification for the proxy connection (USE WITH CAUTION).")

	flag.StringVar(&cfg.TargetCACertFile, "target-ca-cert", "", "Path to a custom CA certificate file for the target (PEM format).")
	flag.StringVar(&cfg.TargetClientCertFile, "target-client-cert", "", "Path to a client certificate file for target mutual TLS (PEM format).")
	flag.StringVar(&cfg.TargetClientKeyFile, "target-client-key", "", "Path to a client private key file for target mutual TLS (PEM format).")
	flag.BoolVar(&cfg.InsecureTargetTLS, "insecure-target-tls", false, "Disable TLS certificate verification for the target connection (USE WITH CAUTION).")

	// flags for timeouts and retries
	flag.DurationVar(&cfg.ConnectTimeout, "connect-timeout", 5*time.Second, "Timeout for establishing a new connection (e.g., 5s, 1m).")
	flag.DurationVar(&cfg.ReadWriteTimeout, "rw-timeout", 30*time.Second, "Timeout for read/write operations on established connections (e.g., 30s, 2m). Set to 0 for no timeout.")
	flag.IntVar(&cfg.MaxRetries, "max-retries", 3, "Maximum number of connection retries on failure (0 for no retries).")
	flag.DurationVar(&cfg.RetryDelay, "retry-delay", 2*time.Second, "Delay between connection retry attempts (e.g., 2s, 500ms).")

	flag.Usage = PrintUsage // Set custom usage function

	flag.Parse()
	return cfg
}

// PrintUsage prints the custom usage message.
func PrintUsage() {
	requiredFlagsOrder := []string{
		"proxy",
	}

	connectionModeFlagsOrder := []string{
		"listen",
		"stdio",
		"socks5",
		"target",
	}

	tlsFlagsOrder := []string{
		"proxy-ca-cert",
		"proxy-client-cert",
		"proxy-client-key",
		"insecure-proxy-tls",
		"target-ca-cert",
		"target-client-cert",
		"target-client-key",
		"insecure-target-tls",
		"target-tls",
	}

	timeoutRetryFlagsOrder := []string{
		"connect-timeout",
		"rw-timeout",
		"max-retries",
		"retry-delay",
	}

	otherOptionalFlagsOrder := []string{
		"proxy-scheme",
		"auth-creds",
		"headers",
		"verbose",
		"silent",
	}

	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  GoProxyTunnel -proxy proxy.example.com:8443 -target 192.168.1.100:8080 -listen 127.0.0.1:25000")
	fmt.Fprintln(os.Stderr, "  GoProxyTunnel -proxy proxy.example.com:8443 -target 192.168.1.100:8080 -stdio")
	fmt.Fprintln(os.Stderr, "  GoProxyTunnel -proxy proxy.example.com:8443 -listen 127.0.0.1:1080 -socks5") // SOCKS5 example

	allFlags := make(map[string]*flag.Flag)
	flag.VisitAll(func(f *flag.Flag) {
		allFlags[f.Name] = f
	})

	fmt.Fprintln(os.Stderr, "\n  Required Parameters (always):")
	for _, name := range requiredFlagsOrder {
		if f, ok := allFlags[name]; ok {
			defaultValue := f.DefValue
			if f.DefValue == "false" || f.DefValue == "true" {
				defaultValue = fmt.Sprintf("%t", f.DefValue == "true")
			}
			fmt.Fprintf(os.Stderr, "    -%s %s\n      %s\n", f.Name, defaultValue, f.Usage)
			delete(allFlags, name)
		}
	}

	fmt.Fprintln(os.Stderr, "\n  Connection Mode Parameters:")
	for _, name := range connectionModeFlagsOrder {
		if f, ok := allFlags[name]; ok {
			defaultValue := f.DefValue
			if f.DefValue == "false" || f.DefValue == "true" {
				defaultValue = fmt.Sprintf("%t", f.DefValue == "true")
			}
			fmt.Fprintf(os.Stderr, "    -%s %s\n      %s\n", f.Name, defaultValue, f.Usage)
			delete(allFlags, name)
		}
	}

	fmt.Fprintln(os.Stderr, "\n  TLS Parameters:")
	for _, name := range tlsFlagsOrder {
		if f, ok := allFlags[name]; ok {
			defaultValue := f.DefValue
			if f.DefValue == "false" || f.DefValue == "true" {
				defaultValue = fmt.Sprintf("%t", f.DefValue == "true")
			}
			fmt.Fprintf(os.Stderr, "    -%s %s\n      %s\n", f.Name, defaultValue, f.Usage)
			delete(allFlags, name)
		}
	}

	fmt.Fprintln(os.Stderr, "\n  Timeout and Retry Parameters:")
	for _, name := range timeoutRetryFlagsOrder {
		if f, ok := allFlags[name]; ok {
			defaultValue := f.DefValue
			if strings.HasSuffix(defaultValue, "0s") || strings.HasSuffix(defaultValue, "0ms") {
				if d, err := time.ParseDuration(defaultValue); err == nil {
					defaultValue = d.String()
				}
			}
			fmt.Fprintf(os.Stderr, "    -%s %s\n      %s\n", f.Name, defaultValue, f.Usage)
			delete(allFlags, name)
		}
	}

	fmt.Fprintln(os.Stderr, "\n  Other Optional Parameters:")
	for _, name := range otherOptionalFlagsOrder {
		if f, ok := allFlags[name]; ok {
			defaultValue := f.DefValue
			if f.DefValue == "false" || f.DefValue == "true" {
				defaultValue = fmt.Sprintf("%t", f.DefValue == "true")
			}
			fmt.Fprintf(os.Stderr, "    -%s %s\n      %s\n", f.Name, defaultValue, f.Usage)
			delete(allFlags, name)
		}
	}

	if len(allFlags) > 0 {
		fmt.Fprintln(os.Stderr, "\n  Unhandled Parameters (alphabetical):")
		// Sort keys for consistent output of unhandled flags
		var unhandledKeys []string
		for k := range allFlags {
			unhandledKeys = append(unhandledKeys, k)
		}
		sort.Strings(unhandledKeys)

		for _, name := range unhandledKeys {
			f := allFlags[name]
			defaultValue := f.DefValue
			if f.DefValue == "false" || f.DefValue == "true" {
				defaultValue = fmt.Sprintf("%t", f.DefValue == "true")
			}
			fmt.Fprintf(os.Stderr, "    -%s %s\n      %s\n", f.Name, defaultValue, f.Usage)
		}
	}
}

// EncodeBase64 is a helper function for encoding strings to Base64.
func EncodeBase64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}
