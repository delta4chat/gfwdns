use crate::*;

pub(crate) const fn v4(a: u8, b: u8, c: u8, d: u8, cidr: u8) -> Subnet {
    Subnet::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), cidr)
}
pub(crate) const fn v6(a: u16, b: u16, c: u16, d: u16, e: u16, f: u16, g: u16, h: u16, cidr: u8) -> Subnet {
    Subnet::new(IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h)), cidr)
}

