use crate::*;

pub const fn ip_split<const V4: usize, const V6: usize>(ips: &[Subnet])
    -> ([Subnet; V4], [Subnet; V6])
{
    let ips_len = ips.len();
    if ips_len != (V4 + V6) {
        panic!("corrupted data");
    }

    let mut ipv4 = [Subnet::default(); V4];
    let mut ipv6 = [Subnet::default(); V6];

    let mut pos4 = 0;
    let mut pos6 = 0;

    let mut ip;
    let mut i = 0;

    while i < ips.len() {
        ip = ips[i];
        if ip.is_ipv4() {
            ipv4[pos4] = ip;
            pos4 += 1;
        } else if ip.is_ipv6() {
            ipv6[pos6] = ip;
            pos6 += 1;
        }
        i += 1;
    }
    
    assert!(pos4 == V4);
    assert!(pos6 == V6);

    (ipv4, ipv6)
}

#[macro_export]
macro_rules! ip_include {
    ($file:literal) => {
        // this "d" variable is needed for avoid include .bin to final output.
        // only the length and parsed Subnet array will be included as static/const rodata.
        pub const IPV4_LEN: usize = {
            let d = include_bytes!($file);
            u32::from_be_bytes([ d[0], d[1], d[2], d[3] ]) as usize
            // "d" leave scope
        };

        pub const IPV6_LEN: usize = {
            let d = include_bytes!($file);
            u32::from_be_bytes([ d[4], d[5], d[6], d[7] ]) as usize
            // "d" leave scope
        };

        pub const IP_LEN: usize = IPV4_LEN + IPV6_LEN;

        pub static IP_LIST: [Subnet; IP_LEN] = {
            let d = include_bytes!($file);
            Subnet::parse_skip(d, IPV4_LEN, 8)
            // "d" leave scope
        };


        static IP46: ([Subnet; IPV4_LEN], [Subnet; IPV6_LEN]) = ip_split(&IP_LIST);
        pub const IPV4_LIST: &[Subnet; IPV4_LEN] = &IP46.0;
        pub const IPV6_LIST: &[Subnet; IPV6_LEN] = &IP46.1;
    }
}
