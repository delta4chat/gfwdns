import sys, ipaddress
def main():
    ip4 = []
    ip6 = []

    s=sys.stdin.read().strip()
    s=[line.strip().split("/") for line in s.split("\n") if len(line) > 0]
    for it in s:
        cidr = int(it[1])
        if ':' in it[0]:
            assert cidr >= 0 and cidr <= 128
            ip = ipaddress.IPv6Address(it[0]).packed + bytes([cidr])
            if ip not in ip6:
                ip6.append(ip)
        elif '.' in it[0]:
            assert cidr >= 0 and cidr <= 32
            ip = ipaddress.IPv4Address(it[0]).packed + bytes([cidr])
            if ip not in ip4:
                ip4.append(ip)

    data = bytearray()

    data.extend(len(ip4).to_bytes(4, 'big'))
    data.extend(len(ip6).to_bytes(4, 'big'))

    for ip in ip4:
        data.extend(ip)

    for ip in ip6:
        data.extend(ip)

    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()

main()

