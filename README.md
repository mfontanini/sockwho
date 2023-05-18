# sockwho

A tool to help determine the (socket) addresses being used by socket syscalls.

---

This uses [aya](https://github.com/aya-rs/aya) to attach eBPF tracepoints to some events like:
* Syscalls that involve `sockaddr` types like `bind` and `connect`.
* The `sock:inet_sock_set_state` event which is called whenever there's a TCP socket changes state.

For every event in the above list it will print a line containing information like the pid, file descriptor, socket
address contents (address and port) and the return value for each syscall.

The output looks something like:

```
Chrome_ChildIOT/135876/53 syscall::bind(0.0.0.0:22317) = 0
Chrome_ChildIOT/135876/53 syscall::connect(127.0.0.53:53) = 0
Chrome_ChildIOT/135876/57 syscall::bind(0.0.0.0:44155) = 0
Chrome_ChildIOT/135876/57 syscall::connect(127.0.0.53:53) = 0
systemd-resolve/912/17 syscall::connect(192.168.0.1:53) = 0
systemd-resolve/912/18 syscall::connect(192.168.0.1:53) = 0
Chrome_ChildIOT/135876 socket::set_state(192.168.0.2:0 <-> 192.30.255.113:443) Close -> SynSent
Chrome_ChildIOT/135876/57 syscall::connect(192.30.255.113:443) = -115 [EINPROGRESS]
```

# Why?

While tools like `strace` give you great insights into what syscalls a process and all of its children are invoking,
they don't let you get information outside that process tree. For example, if I wanted to see which processes are
attempting to bind to a specific port, I wouldn't be able to spot that via strace.

Tools like `perf` allow you to use tracepoints to trace syscalls, but they don't allow expanding the contents of
`sockaddr` pointers being passed in to syscalls (at least not yet).

This tool tries to bridge that gap by letting you trace these syscalls globally and providing insights into what's the
socket address behind each `sockaddr` parameter.

# Building

In order to build _sockwho_, install [rust](https://www.rust-lang.org/) and run

```shell
make release
```

The output binary will be placed in `target/release/sockwho`.

# Running

Simply run the binary to hook into all supported syscalls and events. Otherwise pass a subset of them as an argument:

```shell
# Only trace connect syscalls
sockwho connect
```

# Formats

The formats used for every traced event is:

## Syscalls

```
<process-name>/<pid>/<fd> syscall::<syscall-name>(<socket-address>) = <return code> [errno if applicable]
```

## Socket state events

```
<process-name>/<pid> socket::set_state(<local-address> <-> <remote-address>) <old-tcp-state> -> <new-tcp-state>
```
