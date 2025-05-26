use crate::*;

#[inline(always)]
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
        #[allow(long_running_const_eval)]
        pub const IPV4_LEN: usize = {
            let d = include_bytes!($file);
            u32::from_be_bytes([ d[0], d[1], d[2], d[3] ]) as usize
            // "d" leave scope
        };

        #[allow(long_running_const_eval)]
        pub const IPV6_LEN: usize = {
            let d = include_bytes!($file);
            u32::from_be_bytes([ d[4], d[5], d[6], d[7] ]) as usize
            // "d" leave scope
        };

        pub const IP_LEN: usize = IPV4_LEN + IPV6_LEN;

        #[allow(long_running_const_eval)]
        pub static IP_LIST: [Subnet; IP_LEN] = {
            let d = include_bytes!($file);
            Subnet::parse_skip(d, IPV4_LEN, 8)
            // "d" leave scope
        };

        #[allow(long_running_const_eval)]
        static IP46: ([Subnet; IPV4_LEN], [Subnet; IPV6_LEN]) = ip_split(&IP_LIST);

        pub const IPV4_LIST: &[Subnet; IPV4_LEN] = &IP46.0;
        pub const IPV6_LIST: &[Subnet; IPV6_LEN] = &IP46.1;
    }
}

#[macro_export]
macro_rules! domain_include {
    ($file:literal) => {
        // this "d" variable is needed for avoid include .txt to final output.
        // only the length and parsed &str array will be included as static/const rodata.
        #[allow(long_running_const_eval)]
        pub const DOMAIN_LIST_LEN: usize = {
            let d = include_str!($file);
            domain_count(d)
            // "d" leave scope
        };

        #[allow(long_running_const_eval)]
        pub static DOMAIN_LIST: [&'static str; DOMAIN_LIST_LEN] = {
            let d = include_str!($file);
            domain_parse(d)
            // "d" leave scope
        };
    }
}

#[inline(always)]
pub const fn domain_count(data: &str) -> usize {
    let data = data.as_bytes();
    let data_len = data.len();
    if data_len == 0 {
        return 0;
    }

    let mut count = 0;
    let mut i = 0;
    while i < data_len {
        if data[i] == b'\n' {
            count += 1;
        }
        i += 1;
    }

    if i < (data_len - 1) {
        count += 1;
    }

    count
}

#[inline(always)]
pub const fn domain_parse<'a, const N: usize>(data: &'a str) -> [&'a str; N] {
    let data = data.as_bytes();
    let data_len = data.len();

    let mut out = [""; N];
    if data_len == 0 {
        return out;
    }

    let mut last = 0;
    let mut i = 0;
    let mut ii = 0;
    let mut it;
    while i < data_len {
        if data[i] == b'\n' {
            it = data.split_at(i).0;
            it = it.split_at(last).1;
            if last > 0 {
                it =
                    match it.split_first() {
                        Some(v) => {
                            v.1
                        },
                        _ => {
                            panic!("internal logic error");
                        }
                    };
            }
            it = it.trim_ascii();

            last = i;

            match core::str::from_utf8(it) {
                Ok(v) => {
                    out[ii] = v;
                    ii += 1;
                },
                _ => {
                    panic!("internal logic error");
                }
            }
        }

        i += 1;
    }

    if last < (data_len - 1) {
        it = data.split_at(last).1;
        it =
            match it.split_first() {
                Some(v) => {
                    v.1
                },
                _ => {
                    panic!("internal logic error");
                }
            };
        match core::str::from_utf8(it) {
            Ok(v) => {
                out[ii] = v;
                //ii += 1;
            },
            _ => {
                panic!("internal logic error");
            }
        }
    }

    out
}
