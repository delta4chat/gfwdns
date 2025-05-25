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
