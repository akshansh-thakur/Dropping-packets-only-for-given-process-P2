
# eBPF Process-Specific TCP Filter

An eBPF-based Linux networking project that restricts outgoing IPv4 TCP connection attempts for a selected process.

## Features

- Uses the `cgroup/connect4` eBPF hook.
- Allows a selected process to connect to a configurable TCP destination port.
- Defaults to port 4040.
- Uses a BPF map to configure the allowed port from userspace.
- Leaves other processes unaffected by the process-name filter.

## Requirements

- Linux with eBPF and cgroup v2 support
- Clang/LLVM
- libbpf
- libelf
- GCC
- Make

## Build

```bash
make
```

## Usage

Run with the default allowed port (4040):

```bash
sudo ./loader
```

Configure a different allowed port, such as 8080:

```bash
sudo ./loader 8080
```

## How It Works

1. The userspace loader loads the eBPF program into the kernel.
2. The loader writes the allowed destination port into a BPF map.
3. The program checks the current Linux task name.
4. For the selected process, TCP connection attempts to the configured port are allowed.
5. Attempts to other TCP destination ports are rejected.
6. Other processes and non-TCP protocols are not restricted by this rule.

## Testing

The following behavior was observed during testing:

- Selected process connecting to TCP port 4040: allowed.
- Selected process connecting to TCP port 8080: rejected.
- Another process connecting to TCP port 8080: allowed.

## Limitations

- Filters outgoing IPv4 connection attempts, not every network packet.
- Uses the Linux task name (`comm`), which supports up to 15 visible characters.
- Requires suitable cgroup v2 attachment permissions and kernel support.
- The process-name check is not a strong security identity because a process can change its task name.

## Cleanup

Press `Ctrl+C` in the loader terminal to detach the eBPF program.
