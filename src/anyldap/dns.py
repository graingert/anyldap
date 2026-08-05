"""DNS-related utilities."""

import struct
from socket import inet_aton, inet_ntoa


def aton_octets(ip: str) -> int:
    s = inet_aton(ip)
    value = struct.unpack("!I", s)[0]
    assert isinstance(value, int)
    return value


def aton_numbits(num: int) -> int:
    n = 0
    while num > 0:
        n >>= 1
        n |= 2 ** 31
        num -= 1
    return n


def aton(ip: str | int) -> int:
    try:
        i = int(ip)
    except ValueError:
        assert isinstance(ip, str)
        return aton_octets(ip)
    else:
        return aton_numbits(i)


def ntoa(n: int) -> str:
    s = struct.pack("!I", n)
    ip = inet_ntoa(s)
    return ip


def netmaskToNumbits(netmask: str | int) -> int:
    bits = aton(netmask)
    i = 2 ** 31
    n = 0
    while bits and i > 0:
        if (bits & i) == 0:
            raise RuntimeError("Invalid netmask: %s" % netmask)
        n += 1
        bits -= i
        i = i >> 1
    return n


def ptrSoaName(ip: str | int, netmask: str | int) -> str:
    """
    Convert an IP address and netmask to a CIDR delegation
    -style zone name.
    """
    net = aton(ip) & aton(netmask)

    nmBits = netmaskToNumbits(netmask)
    bytes, bits = divmod(nmBits, 8)
    octets = ntoa(net).split(".")
    octets.reverse()
    if not bits:
        octets = octets[-bytes:]
    else:
        partial = octets[-bytes - 1]
        octets = octets[-bytes:]
        octets.insert(0, "%s/%d" % (partial, nmBits))

    return ".".join(octets) + ".in-addr.arpa."
