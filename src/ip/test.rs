use crate::*;

#[test]
fn ip_list() {
    std::thread::sleep(Duration::from_secs(1));
    dbg!(inside_ips::IPV4_FROM_GEOIP);
    dbg!(inside_ips::IPV6_FROM_GEOIP);

    dbg!(outside_ips::IPV4_FROM_GEOIP);
    dbg!(outside_ips::IPV6_FROM_GEOIP);

}

#[test]
fn ipv4_in_cidr() {
    let ip: Ipv4Addr = "3.0.4.8".parse().unwrap();
    let net = Subnet::new("2.0.0.0".parse().unwrap(), 7);
    assert_eq!(dbg!(net.contains(ip.into())), true);
}

#[test]
fn ipv4_not_in_cidr() {
    let ip: Ipv4Addr = "20.60.89.2".parse().unwrap();
    let net = Subnet::new("128.0.0.0".parse().unwrap(), 1);
    assert_eq!(dbg!(net.contains(ip.into())), false);
}

#[test]
fn ipv4_full_range_cidr_must_not_panic() {
    for cidr in 0..=32 {
        eprintln!("ipv4 cidr={cidr}");
        let ip: Ipv4Addr = "20.60.89.2".parse().unwrap();
        let net = Subnet::new("255.0.0.0".parse().unwrap(), cidr);
        net.contains(ip.into());
    }
}

#[test]
fn ipv6_in_cidr() {
    let ip: Ipv6Addr = "2001:db8:85a3::8a2e:370:7334".parse().unwrap();
    let net = Subnet::new("2000::".parse().unwrap(), 15);
    assert_eq!(dbg!(net.contains(ip.into())), true);
}

#[test]
fn ipv6_not_in_cidr() {
    let ip: Ipv6Addr = "5f0e::2:f".parse().unwrap();
    let net = Subnet::new("fe00::".parse().unwrap(), 1);
    assert_eq!(dbg!(net.contains(ip.into())), false);
}

#[test]
fn ipv6_full_range_cidr_must_not_panic() {
    for cidr in 0..=128 {
        eprintln!("ipv6 cidr={cidr}");
        let ip: Ipv6Addr = "ef00::".parse().unwrap();
        let net = Subnet::new("abcd::".parse().unwrap(), cidr);
        net.contains(ip.into());
    }
}


    #[test]
    fn test_try_new_valid_ipv4() {
        // Valid IPv4
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0));
        let cidr = 24;
        let subnet = Subnet::try_new(ip, cidr);
        assert!(subnet.is_some());
    }

    #[test]
    fn test_try_new_invalid_ipv4() {
        // Invalid CIDR for IPv4
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0));
        let cidr = 33;  // CIDR out of range for IPv4
        let subnet = Subnet::try_new(ip, cidr);
        assert!(subnet.is_none());
    }

    #[test]
    fn test_try_new_valid_ipv6() {
        // Valid IPv6
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0));
        let cidr = 64;
        let subnet = Subnet::try_new(ip, cidr);
        assert!(subnet.is_some());
    }

    #[test]
    fn test_try_new_invalid_ipv6() {
        // Invalid CIDR for IPv6
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0));
        let cidr = 129;  // CIDR out of range for IPv6
        let subnet = Subnet::try_new(ip, cidr);
        assert!(subnet.is_none());
    }

    #[test]
    fn test_is_valid_ipv4() {
        // Test valid CIDR for IPv4
        let subnet = Subnet::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 24);
        assert!(subnet.is_valid());

        // Test invalid CIDR for IPv4
        let subnet = Subnet::try_new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 33);
        assert!(subnet.is_none());
    }

    #[test]
    fn test_is_valid_ipv6() {
        // Test valid CIDR for IPv6
        let subnet = Subnet::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)), 64);
        assert!(subnet.is_valid());

        // Test invalid CIDR for IPv6
        let subnet = Subnet::try_new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)), 129);
        assert!(subnet.is_none());
    }

    #[test]
    fn test_contains_ipv4() {
        let subnet = Subnet::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24);
        
        // IP inside the subnet
        let ip_inside = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(subnet.contains(ip_inside));

        // IP outside the subnet
        let ip_outside = IpAddr::V4(Ipv4Addr::new(192, 169, 1, 1));
        assert!(!subnet.contains(ip_outside));
    }

    #[test]
    fn test_contains_ipv6() {
        let subnet = Subnet::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)), 64);

        // IP inside the subnet
        let ip_inside = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert!(subnet.contains(ip_inside));

        // IP outside the subnet
        let ip_outside = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 0));
        assert!(!subnet.contains(ip_outside));
    }

    #[test]
    fn test_range_ipv4() {
        let subnet = Subnet::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 16);
        let range = subnet.range();
        assert!(range.is_some());

        let (start, end) = range.unwrap();
        assert_eq!(start, IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)));
        assert_eq!(end, IpAddr::V4(Ipv4Addr::new(192, 168, 255, 255)));
    }

    #[test]
    fn test_range_ipv6() {
        let subnet = Subnet::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)), 32);
        let range = subnet.range();
        assert!(range.is_some());

        let (start, end) = range.unwrap();
        assert_eq!(start, IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)));
        assert_eq!(end, IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff)));
    }

    #[test]
    fn test_fill_ipv4() {
        let subnet = Subnet::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 30);
        let mut result = vec![IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)); 4];
        let filled = subnet.fill(&mut result);

        assert_eq!(filled, 4);

        assert_eq!(result[0], IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)));
        assert_eq!(result[1], IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)));
        assert_eq!(result[2], IpAddr::V4(Ipv4Addr::new(192, 168, 0, 2)));
        assert_eq!(result[3], IpAddr::V4(Ipv4Addr::new(192, 168, 0, 3)));
    }

    #[test]
    fn test_random_ipv4() {
        let subnet = Subnet::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 30);
        let random_ip = subnet.random().unwrap();
        assert!(subnet.contains(random_ip)); // Random IP should be within the range
    }

#[test]
fn test_random_ipv6() {
    let subnet = Subnet::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)), 64);
    let random_ip = subnet.random().unwrap();
    assert!(subnet.contains(random_ip)); // Random IP should be within the range
}
