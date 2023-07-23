# sockdig
Sockdig 1.0.0
A socket debug tool. A much more powerful alternative to ss(8)

```
USAGE:
    sockdig [FLAGS] [OPTIONS]

FLAGS:
        --debug      debug log redirected to a local file
    -d, --detail     Print socket info in detail
    -h, --help       Prints help information
    -l, --listen     Print only listning sockets
    -t, --tcp        Print only tcp sockets
    -u, --udp        Print only udp sockets
    -x, --unix       Print only unix sockets
    -4, --v4         Print only IPv4 sockets
    -6, --v6         Print only IPv6 sockets
    -V, --version    Prints version information

OPTIONS:
    -p, --pid <pid>    Print sockets opened by specific process [default: 0]
```