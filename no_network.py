"""For MegaPatch's own checks only: a DETECTOR of attempts to reach another host, not a network barrier.

What it checks, and only in the Python process that called install(), from that moment on:
  - name lookups through socket.getaddrinfo, socket.gethostbyname and socket.gethostbyname_ex
    (urllib, http.client, urllib3, requests and httpx's synchronous client all resolve through getaddrinfo);
  - TCP and UDP connections through socket.socket.connect, socket.socket.connect_ex and socket.create_connection;
  - UDP datagrams sent to an address through socket.socket.sendto and socket.socket.sendmsg.
For AF_INET / AF_INET6 sockets, any host other than this machine (localhost, 127.0.0.0/8, ::1) is refused with
NetworkBlocked before anything is sent, and recorded in ATTEMPTS, so a check can fail if anything tried.

What it does NOT cover (known gaps, so a clean ATTEMPTS is evidence about this process, not proof of isolation):
  - child processes that do not call install() themselves: here Bandit, pytest, the PoCs, git and pip when a check
    runs them (they do not use the network, but this detector does not show it);
  - code that took a reference to the original functions before install() (a module that did
    `from socket import create_connection` before the check installed this), and code that uses the C module
    `_socket` directly, or a socket whose class does not inherit these methods;
  - connections that do not go through socket.connect: asyncio's Windows Proactor loop (it connects with
    _overlapped.ConnectEx), and C extensions with their own network code (libcurl, gRPC's core, and the like);
  - other address families (raw sockets, AF_UNIX, AF_BLUETOOTH...) and a datagram already connected elsewhere;
  - anything at the level of the operating system: it is not a firewall and sets no system rule.
The checks pair it with mocks for every service, so no service call is made in the first place.
"""
import ipaddress
import socket

ATTEMPTS = []
LOCAL_NAMES = {"localhost", "localhost.localdomain"}
INET = (socket.AF_INET, socket.AF_INET6)


class NetworkBlocked(OSError):
    """A check tried to reach another host."""


def _local(host):
    if isinstance(host, bytes):
        host = host.decode(errors="replace")
    if not isinstance(host, str):
        return False
    if host.lower() in LOCAL_NAMES:
        return True
    try:
        return ipaddress.ip_address(host.split("%")[0]).is_loopback
    except ValueError:
        return False


def _refuse(host, port=None):
    ATTEMPTS.append(f"{host}:{port}" if port is not None else str(host))
    raise NetworkBlocked(f"MegaPatch's checks do not use the network: refused {host}"
                         + (f":{port}" if port is not None else ""))


def _host_port(address):
    if isinstance(address, tuple) and address:
        return address[0], (address[1] if len(address) > 1 else None)
    return address, None


def install():
    """Idempotent. Call it before anything else in a check (and in a child process it starts)."""
    if getattr(socket, "_megapatch_no_network", False):
        return
    real = {name: getattr(socket, name) for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex",
                                                      "create_connection")}
    methods = {name: getattr(socket.socket, name) for name in ("connect", "connect_ex", "sendto", "sendmsg")
               if hasattr(socket.socket, name)}

    def lookup(name):
        def check(host, *args, **kwargs):
            if host is not None and not _local(host):
                _refuse(host, args[0] if args else None)
            return real[name](host, *args, **kwargs)
        return check

    def create_connection(address, *args, **kwargs):
        host, port = _host_port(address)
        if not _local(host):
            _refuse(host, port)
        return real["create_connection"](address, *args, **kwargs)

    def to_address(name, position):
        def check(self, *args, **kwargs):
            # sendto(data, address) or sendto(data, flags, address); sendmsg(buffers, ancdata, flags, address);
            # connect(address) and connect_ex(address)
            address = args[-1] if name == "sendto" else (args[position] if len(args) > position else None)
            if self.family in INET and address is not None:
                host, port = _host_port(address)
                if not _local(host):
                    _refuse(host, port)
            return methods[name](self, *args, **kwargs)
        return check

    for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex"):
        setattr(socket, name, lookup(name))
    socket.create_connection = create_connection
    for name, position in (("connect", 0), ("connect_ex", 0), ("sendto", -1), ("sendmsg", 3)):
        if name in methods:
            setattr(socket.socket, name, to_address(name, position))
    socket._megapatch_no_network = True
