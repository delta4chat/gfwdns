pub mod inside_dns;
pub mod outside_dns;

pub mod inside_ips;
pub mod outside_ips;

pub mod inside_domains;
pub mod outside_domains;

pub(crate) mod helper;
pub(crate) use helper::*;

use crate::*;

#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Subnet {
    ip: IpAddr,
    cidr: u8, // 0~32 for IPv4, 0~128 for IPv6.
}
impl Subnet {
    pub const fn try_new(ip: IpAddr, cidr: u8) -> Option<Self> {
        let ip = ip.to_canonical();

        let this = Self { ip, cidr };

        if this.is_valid() {
            Some(this)
        } else {
            None
        }
    }
    pub const fn new(ip: IpAddr, cidr: u8) -> Self {
        if let Some(this) = Self::try_new(ip, cidr) {
            this
        } else {
            panic!("cannot initialize SubnetRange: possible wrong CIDR provided?");
        }
    }

    pub const fn is_valid(&self) -> bool {
        if self.ip.is_ipv4() && self.cidr > 32 {
            false
        } else if self.cidr > 128 {
            false
        } else {
            true
        }
    }

    pub const fn contains(&self, ip: IpAddr) -> bool {
        if ! self.is_valid() {
            return false;
        }

        let ip = ip.to_canonical();

        use IpAddr::*;
        match (self.ip, ip) {
            (V4(ip1), V4(ip2)) => {
                if self.cidr == 0 {
                    return true;
                }
                let mask = u32::MAX.wrapping_shl(32 - self.cidr as u32);
                (ip1.to_bits() & mask) == (ip2.to_bits() & mask)
            },
            (V6(ip1), V6(ip2)) => {
                if self.cidr == 0 {
                    return true;
                }
                let mask = u128::MAX.wrapping_shl(128 - self.cidr as u32);
                (ip1.to_bits() & mask) == (ip2.to_bits() & mask)
            },
            _ => {
                false
            }
        }
    }

    pub /* const */ fn fill(&self, out: &mut [IpAddr]) -> usize {
        let range =
            if let Some(v) = self.range() {
                v
            } else {
                return 0;
            };

        let out_len = out.len();
        if out_len == 0 {
            return 0;
        }

        match range {
            (IpAddr::V4(start), IpAddr::V4(end)) => {
                let start = start.to_bits();
                let end = end.to_bits();

                let mut n = 0;
                while n < out_len {
                    if n >= (u32::MAX as usize) {
                        return n;
                    }

                    let ib4 = start.saturating_add(n as u32);
                    if ib4 > end {
                        return n;
                    }
                    out[n] = IpAddr::V4(Ipv4Addr::from_bits(ib4));
                    n = n.saturating_add(1);
                }
                n
            },
            (IpAddr::V6(start), IpAddr::V6(end)) => {
                let start = start.to_bits();
                let end = end.to_bits();

                let mut n = 0;
                while n < out_len {
                    let ib6 = start.saturating_add(n as u128);

                    if ib6 > (usize::MAX as u128) {
                        return n;
                    }
                    if ib6 > end {
                        return n;
                    }

                    out[n] = IpAddr::V6(Ipv6Addr::from_bits(ib6));
                    n = n.saturating_add(1);
                }
                n
            }

            _ => {
                0
            }
        }
    }

    pub const fn range(&self) -> Option<(IpAddr, IpAddr)> {
        if ! self.is_valid() {
            return None;
        }

        match self.ip {
            IpAddr::V4(ip4) => {
                let start;
                let end;

                if self.cidr == 0 {
                    start = u32::MIN;
                    end = u32::MAX;
                } else if self.cidr == 32 {
                    return Some((self.ip, self.ip));
                } else {
                    start = ip4.to_bits() & u32::MAX.wrapping_shl(32 - self.cidr as u32);
                    end = start.saturating_add(2u32.saturating_pow(32 - self.cidr as u32).saturating_sub(1));
                }

                Some((IpAddr::V4(Ipv4Addr::from_bits(start)), IpAddr::V4(Ipv4Addr::from_bits(end))))
            },
            IpAddr::V6(ip6) => {
                let start;
                let end;

                if self.cidr == 0 {
                    start = u128::MIN;
                    end = u128::MAX;
                } else if self.cidr == 128 {
                    return Some((self.ip, self.ip));
                } else {
                    start = ip6.to_bits() & u128::MAX.wrapping_shl(128 - self.cidr as u32);
                    end = start.saturating_add(2u128.saturating_pow(128 - self.cidr as u32).saturating_sub(1));
                }

                Some((IpAddr::V6(Ipv6Addr::from_bits(start)), IpAddr::V6(Ipv6Addr::from_bits(end))))
            }
        }
    }

    /// generate random IP with in this range
    pub fn random(&self) -> Option<IpAddr> {
        if ! self.is_valid() {
            return None;
        }

        match self.ip {
            IpAddr::V4(ip4) => {
                if self.cidr == 0 {
                    return Some(IpAddr::V4(Ipv4Addr::from_bits(fastrand::u32(..))));
                } else if self.cidr == 32 {
                    return Some(self.ip);
                }

                let start = ip4.to_bits() & u32::MAX.wrapping_shl(32 - self.cidr as u32);
                let end = start.saturating_add(2u32.saturating_pow(32 - self.cidr as u32));

                let ib4 = fastrand::u32(start..end);
                Some(IpAddr::V4(Ipv4Addr::from_bits(ib4)))
            },
            IpAddr::V6(ip6) => {
                if self.cidr == 0 {
                    return Some(IpAddr::V6(Ipv6Addr::from_bits(fastrand::u128(..))));
                } else if self.cidr == 128 {
                    return Some(self.ip);
                }

                let start = ip6.to_bits() & u128::MAX.wrapping_shl(128 - self.cidr as u32);
                let end = start.saturating_add(2u128.saturating_pow(128 - self.cidr as u32));

                let ib6 = fastrand::u128(start..end);
                Some(IpAddr::V6(Ipv6Addr::from_bits(ib6)))
            }
        }
    }
}

pub fn random_inside_ip() -> IpAddr {
    random_inside_ip_by_family(
        if DISABLE_IPV6.load(Relaxed) {
            4
        } else if fastrand::bool() {
            6
        } else {
            4
        }
    )
}
pub fn random_inside_ip_by_family(family: u8) -> IpAddr {
    match family {
        4 => {
            let subnet = inside_ips::IPV4_FROM_GEOIP[fastrand::usize(0..inside_ips::IPV4_FROM_GEOIP.len())];
            subnet.random().unwrap()
        },
        6 => {
            let subnet = inside_ips::IPV6_FROM_GEOIP[fastrand::usize(0..inside_ips::IPV6_FROM_GEOIP.len())];
            subnet.random().unwrap()
        },
        _ => {
            panic!("invalid family provided: it must be 4 or 6.");
        }
    }
}

pub fn random_outside_ip() -> IpAddr {
    random_outside_ip_by_family(
        if DISABLE_IPV6.load(Relaxed) {
            4
        } else if fastrand::bool() {
            6
        } else {
            4
        }
    )
}
pub fn random_outside_ip_by_family(family: u8) -> IpAddr {
    match family {
        4 => {
            let subnet = outside_ips::IPV4_FROM_GEOIP[fastrand::usize(0..outside_ips::IPV4_FROM_GEOIP.len())];
            subnet.random().unwrap()
        },
        6 => {
            let subnet = outside_ips::IPV6_FROM_GEOIP[fastrand::usize(0..outside_ips::IPV6_FROM_GEOIP.len())];
            subnet.random().unwrap()
        },
        _ => {
            panic!("invalid family provided: it must be 4 or 6.");
        }
    }
}

pub fn inside_dns_list() -> Vec<SocketAddr> {
    if DISABLE_IPV6.load(Relaxed) {
        inside_dns_list_by_family(4)
    } else {
        inside_dns::IP_LIST.iter().map(|ip| { SocketAddr::new(*ip, 53) }).collect()
    }
}
pub fn inside_dns_list_by_family(family: u8) -> Vec<SocketAddr> {
    match family {
        4 => {
            inside_dns::IP_LIST.iter().filter(|ip| { ip.is_ipv4() }).map(|ip| { SocketAddr::new(*ip, 53) }).collect()
        },
        6 => {
            inside_dns::IP_LIST.iter().filter(|ip| { ip.is_ipv6() }).map(|ip| { SocketAddr::new(*ip, 53) }).collect()
        },
        _ => {
            panic!("invalid family provided: it must be 4 or 6.");
        }
    }
}

pub fn outside_dns_list() -> Vec<SocketAddr> {
    if DISABLE_IPV6.load(Relaxed) {
        outside_dns_list_by_family(4)
    } else {
        outside_dns::IP_LIST.iter().map(|ip| { SocketAddr::new(*ip, 53) }).collect()
    }
}
pub fn outside_dns_list_by_family(family: u8) -> Vec<SocketAddr> {
    match family {
        4 => {
            outside_dns::IP_LIST.iter().filter(|ip| { ip.is_ipv4() }).map(|ip| { SocketAddr::new(*ip, 53) }).collect()
        },
        6 => {
            outside_dns::IP_LIST.iter().filter(|ip| { ip.is_ipv6() }).map(|ip| { SocketAddr::new(*ip, 53) }).collect()
        },
        _ => {
            panic!("invalid family provided: it must be 4 or 6.");
        }
    }
}

pub fn inside_domain_list() -> Vec<String> {
    inside_domains::LIST.iter().map(|domain| {
        let mut domain = domain.to_string();
        if ! domain.ends_with('.') {
            domain.push('.');
        }
        domain
    }).collect()
}
pub fn outside_domain_list() -> Vec<String> {
    outside_domains::LIST.iter().map(|domain| {
        let mut domain = domain.to_string();
        if ! domain.ends_with('.') {
            domain.push('.');
        }
        domain
    }).collect()
}

#[cfg(test)]
mod test;

