package config

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds all the application's configuration parameters.
type Config struct {
	LocalListenAddrStr string
	ProxyScheme        string
	ProxyAddrStr       string
	TargetAddrStr      string
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

	ConnectTimeout   time.Duration
	ReadWriteTimeout time.Duration
	MaxRetries       int
	RetryDelay       time.Duration

	LocalListenAddr *net.TCPAddr
	ProxyAddr       string
	TargetAddr      string
	CustomHeaders   map[string]string

	ConfigFile string
}

type YAMLConfig struct {
	Workers []struct {
		Listen      string `yaml:"listen"`
		ProxyScheme string `yaml:"proxy_scheme"`
		Proxy       string `yaml:"proxy"`
		Target      string `yaml:"target"`
		TargetTLS   bool   `yaml:"target_tls"`
		Headers     string `yaml:"headers"`
		AuthCreds   string `yaml:"auth_creds"`
		UseStdio    bool   `yaml:"stdio"`
		UseSocks5   bool   `yaml:"socks5"`

		ProxyCACert      string `yaml:"proxy_ca_cert"`
		ProxyClientCert  string `yaml:"proxy_client_cert"`
		ProxyClientKey   string `yaml:"proxy_client_key"`
		InsecureProxyTLS bool   `yaml:"insecure_proxy_tls"`

		TargetCACert      string `yaml:"target_ca_cert"`
		TargetClientCert  string `yaml:"target_client_cert"`
		TargetClientKey   string `yaml:"target_client_key"`
		InsecureTargetTLS bool   `yaml:"insecure_target_tls"`

		ConnectTimeout   string `yaml:"connect_timeout"`
		ReadWriteTimeout string `yaml:"rw_timeout"`
		MaxRetries       int    `yaml:"max_retries"`
		RetryDelay       string `yaml:"retry_delay"`
	} `yaml:"workers"`

	VerboseLog bool `yaml:"verbose_log"`
	SilentLog  bool `yaml:"silent_log"`
}

// ParseFlags parses the command-line arguments and returns a Config struct.
func ParseFlags() *Config {
	cfg := &Config{}

	flag.StringVar(&cfg.LocalListenAddrStr, "listen", "", "Local address and port to listen on (e.g., 127.0.0.1:25000). Required unless -stdio or -config-file is used.")
	flag.StringVar(&cfg.ProxyScheme, "proxy-scheme", "https", "Proxy scheme (http or https)")
	flag.StringVar(&cfg.ProxyAddrStr, "proxy", "", "REQUIRED (unless -config-file): Proxy server address (e.g., proxy.example.com:8443)")
	flag.StringVar(&cfg.TargetAddrStr, "target", "", "Target server address (e.g., 192.168.1.100:8080). Required unless -socks5 or -config-file is used.")
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

	// New flag for YAML configuration file
	flag.StringVar(&cfg.ConfigFile, "config-file", "", "Path to a YAML configuration file. When specified, individual proxy settings should be defined in the file. Global flags like -verbose or -silent still apply.")

	flag.Usage = PrintUsage // Set custom usage function

	flag.Parse()
	return cfg
}

// LoadConfigFromYAML loads configuration from a YAML file.
func LoadConfigFromYAML(filePath string, logger *log.Logger) ([]*Config, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", filePath, err)
	}

	var yamlCfg YAMLConfig
	if err := yaml.Unmarshal(data, &yamlCfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML config from %s: %w", filePath, err)
	}

	var configs []*Config
	for i, worker := range yamlCfg.Workers {
		cfg := &Config{
			LocalListenAddrStr:   worker.Listen,
			ProxyScheme:          worker.ProxyScheme,
			ProxyAddrStr:         worker.Proxy,
			TargetAddrStr:        worker.Target,
			UseTLSOnTarget:       worker.TargetTLS,
			CustomHeadersStr:     worker.Headers,
			AuthorizationCreds:   worker.AuthCreds,
			UseStdio:             worker.UseStdio,
			UseSocks5Proxy:       worker.UseSocks5,
			ProxyCACertFile:      worker.ProxyCACert,
			ProxyClientCertFile:  worker.ProxyClientCert,
			ProxyClientKeyFile:   worker.ProxyClientKey,
			InsecureProxyTLS:     worker.InsecureProxyTLS,
			TargetCACertFile:     worker.TargetCACert,
			TargetClientCertFile: worker.TargetClientCert,
			TargetClientKeyFile:  worker.TargetClientKey,
			InsecureTargetTLS:    worker.InsecureTargetTLS,
			MaxRetries:           worker.MaxRetries,
			VerboseLog:           yamlCfg.VerboseLog,
			SilentLog:            yamlCfg.SilentLog,
		}

		// Parse durations
		if worker.ConnectTimeout != "" {
			d, err := time.ParseDuration(worker.ConnectTimeout)
			if err != nil {
				return nil, fmt.Errorf("worker %d: invalid connect_timeout '%s': %w", i+1, worker.ConnectTimeout, err)
			}
			cfg.ConnectTimeout = d
		} else {
			cfg.ConnectTimeout = 5 * time.Second // Default
		}

		if worker.ReadWriteTimeout != "" {
			d, err := time.ParseDuration(worker.ReadWriteTimeout)
			if err != nil {
				return nil, fmt.Errorf("worker %d: invalid rw_timeout '%s': %w", i+1, worker.ReadWriteTimeout, err)
			}
			cfg.ReadWriteTimeout = d
		} else {
			cfg.ReadWriteTimeout = 30 * time.Second // Default
		}

		if worker.RetryDelay != "" {
			d, err := time.ParseDuration(worker.RetryDelay)
			if err != nil {
				return nil, fmt.Errorf("worker %d: invalid retry_delay '%s': %w", i+1, worker.RetryDelay, err)
			}
			cfg.RetryDelay = d
		} else {
			cfg.RetryDelay = 2 * time.Second // Default
		}

		configs = append(configs, cfg)
	}

	if len(configs) == 0 {
		return nil, fmt.Errorf("no workers defined in the configuration file %s", filePath)
	}

	return configs, nil
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
		"config-file",
	}

	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  GoProxyTunnel -proxy proxy.example.com:8443 -target 192.168.1.100:8080 -listen 127.0.0.1:25000")
	fmt.Fprintln(os.Stderr, "  GoProxyTunnel -proxy proxy.example.com:8443 -target 192.168.1.100:8080 -stdio")
	fmt.Fprintln(os.Stderr, "  GoProxyTunnel -proxy proxy.example.com:8443 -listen 127.0.0.1:1080 -socks5") // SOCKS5 example
	fmt.Fprintln(os.Stderr, "  GoProxyTunnel -config-file /path/to/your/config.yaml")                       // YAML config example

	allFlags := make(map[string]*flag.Flag)
	flag.VisitAll(func(f *flag.Flag) {
		allFlags[f.Name] = f
	})

	fmt.Fprintln(os.Stderr, "\n  Required Parameters (always, or in config file):")
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

// Helper function for encoding strings to Base64.
func EncodeBase64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}
