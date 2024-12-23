BASE63_CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789"
def int_to_base63(n):
    if n == 0:
        return BASE63_CHARSET[0]
    
    base63_str = ''
    while n > 0:
        base63_str = BASE63_CHARSET[n % 63] + base63_str
        n //= 63

    if base63_str[0].isdigit():
        base63_str = 'a' + base63_str
    return base63_str

def base63_to_int(base63_str):
    n = 0
    for char in base63_str:
        n = n * 63 + BASE63_CHARSET.index(char)
    return n

import sys, ipaddress
def main():
    maps4 = {}
    maps6 = {}

    ipv4 = [ "pub const IPV4_FROM_GEOIP: &'static [Subnet] = &[" ]
    ipv6 = [ "pub const IPV6_FROM_GEOIP: &'static [Subnet] = &[" ]

    s=sys.stdin.read().strip()

    s=[line.strip().split("/") for line in s.split("\n") if len(line) > 0]

    c = 0
    keywords = ('else', 'enum', 'abstract', 'impl', 'let', 'unsafe', 'priv', 'mod', 'true', 'macro_rules', 'self', 'as', 'virtual', 'move', 'if', 'macro', 'crate', 'extern', 'fn', 'pub', 'struct', 'trait', 'break', 'use', 'while', 'yield', 'dyn', 'await', 'try', 'continue', 'false', 'in', 'static', 'unsized', 'typeof', 'Self', 'box', 'ref', 'super', 'const', 'type', 'async', 'for', 'loop', 'do', 'final', 'override', 'match', 'become', 'return', 'mut', 'where', 'union', 'gen', 'generator', 'v4', 'v6', 'm4', 'm6', '_', 'u8', 'u16', 'u32', 'u64', 'usize', 'u128', 'i8', 'i16', 'i32', 'i64', 'isize', 'i128', 'f32', 'f64', 'f16')
    for it in s:
        if ':' in it[0]:
            ip = ipaddress.IPv6Address(it[0]).exploded.split(':')
            parts = [int(i, 16) for i in ip]
            for i in range(len(parts)):
                bc = c+0
                ii = parts[i]
                #ib = int_to_base63(ii)
                if ii not in maps6:
                    cb = '0'
                    while cb[0].isdigit() or (cb in keywords):
                        cb = int_to_base63(c)
                        c += 1
                    maps6[ii] = (cb, ('%s,%d,' % (cb, ii)))
                if len(maps6[ii][0]) < len(str(parts[i])):
                    parts[i] = maps6[ii][0]
                else:
                    parts[i] = str(parts[i])
                    del maps6[ii]
                    c = bc

            cidr = int(it[1])
            ipv6.append('v6(%s,%s,%s,%s,%s,%s,%s,%s,%d),//IPv6=%s' % (*parts, cidr, it[0]+'/'+it[1]))
        elif '.' in it[0]:
            ip = ipaddress.IPv4Address(it[0])
            parts = list(ip.packed)
            for i in range(len(parts)):
                bc = c+0
                ii = parts[i]
                #ib = int_to_base63(ii)
                if ii not in maps4:
                    cb = '0'
                    while cb[0].isdigit() or (cb in keywords):
                        cb = int_to_base63(c)
                        c += 1
                    maps4[ii] = (cb, ('%s,%d,' % (cb, ii)))
                if len(maps4[ii][0]) < len(str(parts[i])):
                    parts[i] = maps4[ii][0]
                else:
                    parts[i] = str(parts[i])
                    del maps4[ii]
                    c = bc

            cidr = int(it[1])
            ipv4.append('v4(%s,%s,%s,%s,%d),//IPv4=%s' % (*parts, cidr, it[0]+'/'+it[1]))

    ipv4.append('];')
    ipv6.append('];')

    print(*ipv4, sep='\n')
    print(*ipv6, sep='\n')

    m4 = 'm4!('
    for v in maps4.values():
        m4 += v[1]
    m4 += ');'

    m6 = 'm6!('
    for v in maps6.values():
        m6 += v[1]
    m6 += ');'

    print(m4)
    print(m6)

main()

