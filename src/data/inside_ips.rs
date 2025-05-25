use crate::*;

/* CN: IPv4+IPv6 */

static DATA: &[u8] = include_bytes!("inside_ips.bin");

pub const IPV4_LEN: usize = u32::from_be_bytes([ DATA[0], DATA[1], DATA[2], DATA[3] ]) as usize;
pub const IPV6_LEN: usize = u32::from_be_bytes([ DATA[4], DATA[5], DATA[6], DATA[7] ]) as usize;
pub const IP_LEN: usize = IPV4_LEN + IPV6_LEN;

pub static IP_LIST: [Subnet; IP_LEN] = Subnet::parse_skip(DATA, IPV4_LEN, 8);

static IP46: ([Subnet; IPV4_LEN], [Subnet; IPV6_LEN]) = ip_split(&IP_LIST);
pub const IPV4_LIST: &[Subnet; IPV4_LEN] = &IP46.0;
pub const IPV6_LIST: &[Subnet; IPV6_LEN] = &IP46.1;

