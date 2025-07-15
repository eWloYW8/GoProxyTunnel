# GoProxyTunnel

GoProxyTunnel is a lightweight and versatile TCP proxy tunnel built in Go. It enables you to tunnel TCP connections through an HTTP or HTTPS proxy using the `CONNECT` method.

## Installation

```bash
git clone https://github.com/eWloYW8/GoProxyTunnel
cd GoProxyTunnel
go build
```

This will create an executable named `GoProxyTunnel` (or `GoProxyTunnel.exe` on Windows) in your current directory.

## Usage

```bash
./GoProxyTunnel [OPTIONS]
```

### Examples

**1. Listening on a local port and proxying via HTTPS:**

```bash
./GoProxyTunnel -proxy proxy.example.com:8443 -target 192.168.1.100:8080 -listen 127.0.0.1:25000
```

In this example, any connection to `127.0.0.1:25000` will be proxied through `proxy.example.com:8443` to `192.168.1.100:8080`.

**2. Using stdin/stdout with proxy authentication and verbose logging:**

```bash
echo "Hello Target!" | ./GoProxyTunnel -proxy myproxy.com:8080 -target remote.service.com:443 -auth-creds "user:pass" -target-tls -stdio -verbose
```

This command sends "Hello Target\!" via `stdin`, tunnels it through `myproxy.com:8080` (with authentication) to `remote.service.com:443` (with TLS on the target connection), and prints the response to `stdout`. Verbose logging will show detailed connection information.

**3. Adding custom headers:**

```bash
./GoProxyTunnel -proxy proxy.example.com:8443 -target internal.app.com:80 -listen 0.0.0.0:1080 -headers "User-Agent:MyProxyClient,X-Custom-ID:12345"
```

This sets up a listener on `0.0.0.0:1080` and adds `User-Agent` and `X-Custom-ID` headers to the `CONNECT` request sent to the proxy.

**4. Using GoProxyTunnel as an SSH `ProxyCommand`:**

```bash
ssh user@your-target-ip -o "ProxyCommand ./GoProxyTunnel -proxy proxy.example.com:8443 -target %h:%p -auth-creds 'your_username:your_password' -stdio -silent"
```

This command configures SSH to use `GoProxyTunnel` as a `ProxyCommand`. It tunnels your SSH connection to `your-target-ip` through `proxy.example.com:8443`, using the provided credentials. The `-stdio` and `-silent` flags are crucial for `ProxyCommand` integration to ensure standard I/O is used and no extraneous logs interfere with SSH. `%h` and `%p` are SSH placeholders for the target host and port.

### Command-Line Arguments

GoProxyTunnel offers several command-line flags to configure its behavior:

| Flag                 | Description                                                                                                                                           | Default       | Required                       |
| :------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------- | :------------ | :----------------------------- |
| `-proxy`             | **REQUIRED:** Proxy server address (e.g., `proxy.example.com:8443`).                                                                                    |               | Yes                            |
| `-target`            | **REQUIRED:** Target server address (e.g., `192.168.1.100:8080`).                                                                                         |               | Yes                            |
| `-listen`            | Local address and port to listen on (e.g., `127.0.0.1:25000`). Required unless `-stdio` is used.                                                          | `""`          | Yes (unless `-stdio` is used)  |
| `-stdio`             | Use `stdin`/`stdout` for communication instead of listening on a network address. Conflicts with `-listen`. Recommend using `-silent` with this flag. | `false`       | Yes (unless `-listen` is used) |
| `-proxy-scheme`      | Proxy scheme (`http` or `https`).                                                                                                                     | `https`       | No                             |
| `-target-tls`        | Whether to use TLS on the target connection after the proxy tunnel is established.                                                                      | `false`       | No                             |
| `-auth-creds`        | Proxy-Authorization credentials (format: `"username:password"`). Will be Base64 encoded automatically.                                                | `""`          | No                             |
| `-headers`           | Comma-separated custom request headers (e.g., `"User-Agent:GoProxy,X-Forwarded-For:1.2.3.4"`).                                                         | `""`          | No                             |
| `-verbose`           | Enable verbose logging to `stderr`.                                                                                                                   | `false`       | No                             |
| `-silent`            | Disable all logging output to `stderr`. Recommended when using `-stdio`.                                                                               | `false`       | No                             |

