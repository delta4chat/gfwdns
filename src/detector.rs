use crate::*;

pub const ROOT_SERVERS: &'static [(&'static str, Ipv4Addr, Ipv6Addr)] = &[
    // domain=a.root-servers.net. | ipv4=198.41.0.4 | ipv6=2001:503:ba3e::2:30
    (
        "a.root-servers.net.",
        Ipv4Addr::new(198, 41, 0, 4),
        Ipv6Addr::new(0x2001, 0x0503, 0xba3e, 0x0000, 0x0000, 0x0000, 0x0002, 0x0030)
    ),

    // domain=b.root-servers.net. | ipv4=170.247.170.2 | ipv6=2801:1b8:10::b
    (
        "b.root-servers.net.",
        Ipv4Addr::new(170, 247, 170, 2),
        Ipv6Addr::new(0x2801, 0x01b8, 0x0010, 0x0000, 0x0000, 0x0000, 0x0000, 0x000b)
    ),

    // domain=c.root-servers.net. | ipv4=192.33.4.12 | ipv6=2001:500:2::c
    (
        "c.root-servers.net.",
        Ipv4Addr::new(192, 33, 4, 12),
        Ipv6Addr::new(0x2001, 0x0500, 0x0002, 0x0000, 0x0000, 0x0000, 0x0000, 0x000c)
    ),

    // domain=d.root-servers.net. | ipv4=199.7.91.13 | ipv6=2001:500:2d::d
    (
        "d.root-servers.net.",
        Ipv4Addr::new(199, 7, 91, 13),
        Ipv6Addr::new(0x2001, 0x0500, 0x002d, 0x0000, 0x0000, 0x0000, 0x0000, 0x000d)
    ),

    // domain=e.root-servers.net. | ipv4=192.203.230.10 | ipv6=2001:500:a8::e
    (
        "e.root-servers.net.",
        Ipv4Addr::new(192, 203, 230, 10),
        Ipv6Addr::new(0x2001, 0x0500, 0x00a8, 0x0000, 0x0000, 0x0000, 0x0000, 0x000e)
    ),

    // domain=f.root-servers.net. | ipv4=192.5.5.241 | ipv6=2001:500:2f::f
    (
        "f.root-servers.net.",
        Ipv4Addr::new(192, 5, 5, 241),
        Ipv6Addr::new(0x2001, 0x0500, 0x002f, 0x0000, 0x0000, 0x0000, 0x0000, 0x000f)
    ),

    // domain=g.root-servers.net. | ipv4=192.112.36.4 | ipv6=2001:500:12::d0d
    (
        "g.root-servers.net.",
        Ipv4Addr::new(192, 112, 36, 4),
        Ipv6Addr::new(0x2001, 0x0500, 0x0012, 0x0000, 0x0000, 0x0000, 0x0000, 0x0d0d)
    ),

    // domain=h.root-servers.net. | ipv4=198.97.190.53 | ipv6=2001:500:1::53
    (
        "h.root-servers.net.",
        Ipv4Addr::new(198, 97, 190, 53),
        Ipv6Addr::new(0x2001, 0x0500, 0x0001, 0x0000, 0x0000, 0x0000, 0x0000, 0x0053)
    ),

    // domain=i.root-servers.net. | ipv4=192.36.148.17 | ipv6=2001:7fe::53
    (
        "i.root-servers.net.",
        Ipv4Addr::new(192, 36, 148, 17),
        Ipv6Addr::new(0x2001, 0x07fe, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0053)
    ),

    // domain=j.root-servers.net. | ipv4=192.58.128.30 | ipv6=2001:503:c27::2:30
    (
        "j.root-servers.net.",
        Ipv4Addr::new(192, 58, 128, 30),
        Ipv6Addr::new(0x2001, 0x0503, 0x0c27, 0x0000, 0x0000, 0x0000, 0x0002, 0x0030)
    ),

    // domain=k.root-servers.net. | ipv4=193.0.14.129 | ipv6=2001:7fd::1
    (
        "k.root-servers.net.",
        Ipv4Addr::new(193, 0, 14, 129),
        Ipv6Addr::new(0x2001, 0x07fd, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001)
    ),

    // domain=l.root-servers.net. | ipv4=199.7.83.42 | ipv6=2001:500:9f::42
    (
        "l.root-servers.net.",
        Ipv4Addr::new(199, 7, 83, 42),
        Ipv6Addr::new(0x2001, 0x0500, 0x009f, 0x0000, 0x0000, 0x0000, 0x0000, 0x0042)
    ),

    // domain=m.root-servers.net. | ipv4=202.12.27.33 | ipv6=2001:dc3::35
    (
        "m.root-servers.net.",
        Ipv4Addr::new(202, 12, 27, 33),
        Ipv6Addr::new(0x2001, 0x0dc3, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0035)
    ),
];
pub const ROOT_SERVERS_LEN: usize = ROOT_SERVERS.len();

pub const ROOT_SERVERS_IPV4: [(&'static str, Ipv4Addr); ROOT_SERVERS_LEN] = {
    let mut list = [("", Ipv4Addr::UNSPECIFIED); ROOT_SERVERS_LEN];

    let mut i = 0;
    while i < ROOT_SERVERS_LEN {
        list[i] = (ROOT_SERVERS[i].0, ROOT_SERVERS[i].1);
        i += 1;
    }

    list
};
pub const ROOT_SERVERS_IPV6: [(&'static str, Ipv6Addr); ROOT_SERVERS_LEN] = {
    let mut list = [("", Ipv6Addr::UNSPECIFIED); ROOT_SERVERS_LEN];

    let mut i = 0;
    while i < ROOT_SERVERS_LEN {
        list[i] = (ROOT_SERVERS[i].0, ROOT_SERVERS[i].2);
        i += 1;
    }

    list
};

pub const fn root_servers_addr_by_family(family: u8) -> [SocketAddr; ROOT_SERVERS_LEN] {
    let mut list = [const { SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0) }; ROOT_SERVERS_LEN];

    let mut i = 0;
    while i < ROOT_SERVERS_LEN {
        if family == 4 {
            list[i] = SocketAddr::new(IpAddr::V4(ROOT_SERVERS_IPV4[i].1), 53);
        } else if family == 6 {
            list[i] = SocketAddr::new(IpAddr::V6(ROOT_SERVERS_IPV6[i].1), 53);
        } else {
            panic!("caller provided non-IPv4 and non-IPv6 IP family");
        }

        i += 1;
    }

    list
}
pub const fn root_servers_addr() -> [SocketAddr; ROOT_SERVERS_LEN * 2] {
    let mut list = [const { SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0) }; ROOT_SERVERS_LEN * 2];

    let mut pos = 0;

    let v4 = root_servers_addr_by_family(4);
    let mut i = 0;
    while i < ROOT_SERVERS_LEN {
        list[pos] = v4[i];

        pos += 1;
        i += 1;
    }

    let v6 = root_servers_addr_by_family(6);
    i = 0;
    while i < ROOT_SERVERS_LEN {
        list[pos] = v6[i];

        pos += 1;
        i += 1;
    }

    list
}

pub fn scc_hashset_of_root_servers() -> Arc<scc::HashSet<SocketAddr>> {
    let map = scc::HashSet::new();
    for adr in root_servers_addr() {
        let _ = map.insert(adr);
    }
    Arc::new(map)
}

/// for ResetFromTcp, ResponseFromUdpBlackhole: all IpAddr should outside the GFW, e.g. non-China IPs.
///
/// for EmptySoaFromLocal: all IpAddr should inside the GFW, e.g. China IPs.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomainSpoofDetectMethod {
    /// [recommended: this is the most (98%) reliable way: if all outgoing TCP 53 traffic has been dropped, then the result is not reliable]
    /// if any TCP RST from established TCP connection, then assume that domain is blocked. This requires the Remote IP is accepting TCP 53 connections, so any DNS server should matches this requirement.
    ResetFromTcp,

    /// [recommended: this is the most (95%) reliable way: if all outgoing UDP 53 traffic has been dropped, then the result is not reliable]
    /// this does not requires target is UDP blackhole (it works fine if specified online IPs). 
    /// Send UDP query with "domain.com IN HINFO" to Global IPs, if received response with any of A or AAAA record, assume that domain is blocked.
    IpFromNonRdtypeA,

    /// [may recommended (90%) reliable: if all outgoing UDP 53 has been drops, or the specified IPs is online and response to UDP 53, then the result is not reliable]
    /// if any response from UDP blackhole, then assume that domain is blocked by DNS spoofing. This requires the Remote IP is never response to incoming UDP 53 traffic, so any offline host should matches this requirement.
    ResponseFromUdpBlackhole,

    /// [recommended: this definitely a (90%) reliable way, but false-negative is possible, because maybe some blocked domain not in this gfwlist]
    /// a pre-defined list of GFW-blocked domains. if any domain in this list, then assume that domain is blocked. this does not requires Internet access.
    GfwList,

    /// [may not recommended (80%) reliable: this behavior may changes in future]
    /// Send UDP query with "domain.com IN SOA" to local DNS servers (any server located in China), if received response is empty (without records), then assume that domain is blocked. because these DNS servers is inside the GFW, so their query is spoofed by GFW (even rdtype is not A or AAAA), so they should received a answer with A record, this is not valid response of SOA query (due to rdtype mis-match). and the most of domains should have SOA records even NXDOMAIN.
    EmptySoaFromLocal,

    /// [not recommended: this may (95%) reliable but DDoS to Root NS]
    /// Send UDP qeury with "domain.com CH A" (rdclass=Chaos, rdtype=A) to 13 root servers, if received any of IP address (A or AAAA), then assume that domain is blocked. because any of *.root-servers.net does not handle Chaos, and does not respond any IP address other than them self (*.root-servers.net) or GTLD/CCTLD (.com / .org / .net / .cc, etc.).
    ResponseIpFromRootNS,
}

impl core::str::FromStr for DomainSpoofDetectMethod {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        Self::parse_str(s)
    }
}

impl TryFrom<&str> for DomainSpoofDetectMethod {
    type Error = anyhow::Error;

    fn try_from(s: &str) -> anyhow::Result<Self> {
        Self::parse_str(s)
    }
}

impl DomainSpoofDetectMethod {
    pub fn parse_str(method: &str) -> anyhow::Result<Self> {
        Ok(match method.replace("_", "-").replace(".", "-").replace(" ", "-").to_lowercase().as_str() {
            "tcp-rst" | "tcp-reset"
                => Self::ResetFromTcp,

            "ip-from-non-rdtype-a" | "ip-from-hinfo"
                => Self::IpFromNonRdtypeA,

            "response-from-udp-blackhole" | "resp-from-udp-blackhole" | "udp-blackhole"
                => Self::ResponseFromUdpBlackhole,

            "gfw-list" | "gfwlist"
                => Self::GfwList,

            "empty-soa-from-local" | "empty-soa-local" | "empty-soa"
                => Self::EmptySoaFromLocal,

            "response-ip-from-root-ns" | "root-ns" | "root"
                => Self::ResponseIpFromRootNS,

            _ => {
                anyhow::bail!("unknown DomainSpoofDetectMethod {method:?} provided!");
            },
        })
    }

    pub const fn is_dynamic(&self) -> bool {
        match self {
            Self::GfwList => false,
            _ => true
        }
    }
    pub const fn is_static(&self) -> bool {
        ! self.is_dynamic()
    }

    pub fn best_dynamic() -> (Self, DomainSpoofDetectData) {
        let ips = outside_dns_list();
        let list = DomainSpoofDetectAddressList::new(GfwSide::Outside, Some(ips.iter().copied()));
        let data = DomainSpoofDetectData::Address(list);
        (Self::ResetFromTcp, data)
    }
    pub fn best_static() -> (Self, DomainSpoofDetectData) {
        (Self::GfwList, todo!())
    }
}

#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub enum GfwSide {
    /// any China IP should inside the GFW
    Inside,

    /// any non-China (Global) IP should outside the GFW
    Outside,
}

#[derive(Clone, Debug)]
pub struct DomainSpoofDetectAddressList {
    list: Arc<scc::HashSet<SocketAddr>>,
    side: GfwSide,
}

impl DomainSpoofDetectAddressList {
    pub fn new(side: GfwSide, maybe_addrs: Option<impl Iterator<Item=SocketAddr>>) -> Self {
        let list = Arc::new(scc::HashSet::new());
        if let Some(addrs) = maybe_addrs {
            for addr in addrs {
                let _ = list.insert(addr);
            }
        } else {
            let mut i = 0u16;
            let mut ip;
            while list.len() < 1000 && i < 10000 {
                ip =
                    match side {
                        GfwSide::Inside => { random_inside_ip() },
                        GfwSide::Outside => { random_outside_ip() },
                    };
                let _ = list.insert(SocketAddr::new(ip, 53));
                i += 1;
            }
        }

        Self { list, side }
    }

    pub fn inside(maybe_addrs: Option<impl Iterator<Item=SocketAddr>>) -> Self {
        Self::new(GfwSide::Inside, maybe_addrs)
    }

    pub fn outside(maybe_addrs: Option<impl Iterator<Item=SocketAddr>>) -> Self {
        Self::new(GfwSide::Outside, maybe_addrs)
    }
}

#[derive(Clone, Debug)]
pub enum DomainSpoofDetectData {
    Address(DomainSpoofDetectAddressList),
    Domain(Arc<scc::HashSet<String>>),
    None,
}
impl DomainSpoofDetectData {
    pub fn as_domain(&self) -> Option<Arc<scc::HashSet<String>>> {
        match self {
            Self::Domain(domains) => {
                Some(domains.clone())
            },
            _ => {
                None
            }
        }
    }

    pub fn as_address(&self) -> Option<Arc<scc::HashSet<SocketAddr>>> {
        match self {
            Self::Address(addrs) => {
                Some(addrs.list.clone())
            },
            _ => {
                None
            }
        }
    }
    pub async fn select_addr_by_family(&self, family: u8) -> Option<SocketAddr> {
        let addrs = self.as_address()?;
        let addrs = {
            let mut x: Vec<SocketAddr> = Vec::new();
            addrs.scan_async(|addr| {
                x.push(*addr);
            }).await;
            x
        };

        match family {
            4 => {
                let ipv4s: Vec<SocketAddr> = addrs.into_iter().filter(|addr| { addr.is_ipv4() }).collect();
                if ipv4s.is_empty() {
                    None
                } else {
                    Some(ipv4s[fastrand::usize(0 .. ipv4s.len())])
                }
            },
            6 => {
                let ipv6s: Vec<SocketAddr> = addrs.into_iter().filter(|addr| { addr.is_ipv6() }).collect();
                if ipv6s.is_empty() {
                    None
                } else {
                    Some(ipv6s[fastrand::usize(0 .. ipv6s.len())])
                }
            },
            _ => {
                panic!("caller provided non-IPv4 and non-IPv6 IP family");
            }
        }
    }
    pub async fn select_addr(&self) -> Option<SocketAddr> {
        let family =
            if DISABLE_IPV6.load(Relaxed) {
                4
            } else if fastrand::bool() {
                6
            } else {
                4
            };

        self.select_addr_by_family(family).await
    }

    pub async fn addrs(&self) -> Vec<SocketAddr> {
        let mut out = Vec::new();
        let addrs =
            match self.as_address() {
                Some(val) => val,
                _ => {
                    return out;
                }
            };
        addrs.scan_async(|addr| {
            out.push(*addr);
        }).await;
        out
    }
}

#[derive(Clone, Debug)]
pub struct DomainSpoofDetector {
    method: DomainSpoofDetectMethod, data: DomainSpoofDetectData,

    cache: DomainStatusCache,
}
impl DomainSpoofDetector {
    pub async fn new(
        method: DomainSpoofDetectMethod,
        data: DomainSpoofDetectData,
        maybe_cache: Option<DomainStatusCache>
    ) -> anyhow::Result<Self> {
        use DomainSpoofDetectMethod::*;
        match method {
            ResetFromTcp | ResponseFromUdpBlackhole | EmptySoaFromLocal | IpFromNonRdtypeA => {
                if let DomainSpoofDetectData::Address(ref addrs) = data {
                    if method == EmptySoaFromLocal {
                        if addrs.side != GfwSide::Inside {
                            anyhow::bail!("method requires a list of IPs that inside the GFW, but this IP list is outside");
                        }
                    } else {
                        if addrs.side != GfwSide::Outside {
                            anyhow::bail!("method requires a list of IPs that outside the GFW, but this IP list is inside");
                        }
                    }

                    if DISABLE_IPV6.load(Relaxed) {
                        if data.select_addr_by_family(4).await.is_none() {
                            anyhow::bail!("DISABLE_IPV6 is set, but provided IP list is no IPv4 found.");
                        }
                    }

                    if data.select_addr().await.is_none() {
                        anyhow::bail!("provided IP list is empty.");
                    }
                } else {
                    anyhow::bail!("method requires a list of IPs, but data != Address");
                }
            },
            GfwList => {
                if let DomainSpoofDetectData::Domain(_) = data { // that is ok
                } else {
                    anyhow::bail!("method requires a list of domains, but data != Domains");
                }
            },
            ResponseIpFromRootNS => {
                if let DomainSpoofDetectData::None = data { // that is ok
                } else {
                    log::warn!("method does not requires any of data, but provided some data, so ignore it."); // that is also ok but should warns
                }
            }
        }

        Ok(Self {
            method, data,
            cache: maybe_cache.unwrap_or_else(Default::default),
        })
    }

    fn _gen_dns_query(domain: &str, rdclass: u16, rdtype: u16) -> anyhow::Result<dns::Message> {
        Ok(
            dns::Message::new()
            .set_id(fastrand::u16(..))
            .set_message_type(dns::MessageType::Query)
            .set_op_code(dns::OpCode::Query)
            .set_recursion_desired(true)
            .set_recursion_available(false)
            .set_authentic_data(false)
            .set_checking_disabled(false)
            .add_query(
                dns::Query::new()
                .set_name(dns::Name::from_str_relaxed(domain)?)
                .set_query_class(rdclass.into())
                .set_query_type(rdtype.into())
                .to_owned()
            )
            .to_owned()
        )
    }

    /// cached detect: return bool means "is_spoofed":
    /// 1. if returns true, this domain is blocked by DNS spoofing.
    /// 2. if returns false, this domain is not blocked by DNS spoofing. NOTE: this does not check other censorship methods (such as TLS-SNI-TCP-RST, IP-blackhole, or HTTP-TCP-RST)
    pub async fn detect(&self, domain: impl ToString) -> anyhow::Result<bool> {
        let mut domain = domain.to_string().to_lowercase();
        if ! domain.ends_with('.') {
            domain.push('.');
        }

        if let Ok(info) = self.cache.get(&domain).await {
            let is_blocked = info.is_blocked();

            if info.is_expired() {
                log::warn!("status info for domain {:?} is expired, update at background...", &domain);

                let this = self.clone();
                smolscale2::spawn(async move {
                    let is_blocked = this._detect(&domain).await.unwrap();
                    let _ = this.cache.put(&domain, is_blocked, this.method).await;
                }).detach();
            }
            return Ok(is_blocked);
        }

        let is_blocked = self._detect(&domain).await?;

        let _ = self.cache.put(&domain, is_blocked, self.method).await;
        Ok(is_blocked)
    }

    /// un-cached detect
    async fn _detect(&self, domain: &str) -> anyhow::Result<bool> {
        use DomainSpoofDetectMethod::*;
        match &self.method {
            ResponseFromUdpBlackhole => {
                let mut addr =
                    match self.data.select_addr().await {
                        Some(v) => v,
                        _ => {
                            anyhow::bail!("no (global IP) remote address provided...");
                        }
                    };

                let udp =
                    if addr.is_ipv4() {
                        UdpSocket::bind("0.0.0.0:0").await?
                    } else {
                        UdpSocket::bind("[::]:0").await?
                    };

                let mut addrs = Vec::new();

                let mut buf: [u8; 1] = [0];
                for _ in 0..20 {
                    let msg = Self::_gen_dns_query(&domain, 1, 1)?; // IN(1) A(1)

                    udp.send_to(msg.to_vec()?.as_ref(), addr).await?;
                    addrs.push(addr);

                    addr =
                        match self.data.select_addr_by_family(if addr.is_ipv4() { 4 } else { 6 }).await {
                            Some(v) => v,
                            _ => {
                                anyhow::bail!("no (global IP) remote address provided...");
                            }
                        };

                    if let Some(Ok((_len, peer))) = udp.recv_from(&mut buf).timeout(Duration::from_millis(250)).await {
                        if ! addrs.contains(&peer) {
                            continue;
                        }

                        return Ok(true);
                    }
                }
                Ok(false)
            },
            IpFromNonRdtypeA => {
                let mut addr =
                    match self.data.select_addr().await {
                        Some(v) => v,
                        _ => {
                            anyhow::bail!("no (global IP) remote address provided...");
                        }
                    };

                let udp =
                    if addr.is_ipv4() {
                        UdpSocket::bind("0.0.0.0:0").await?
                    } else {
                        UdpSocket::bind("[::]:0").await?
                    };

                let mut addrs = Vec::new();

                let mut buf = vec![0u8; 65535];
                for _ in 0..20 {
                    let msg = Self::_gen_dns_query(&domain, 1, 13)?; // IN(1) HINFO(13)

                    udp.send_to(msg.to_vec()?.as_ref(), addr).await?;
                    addrs.push(addr);

                    addr =
                        match self.data.select_addr_by_family(if addr.is_ipv4() { 4 } else { 6 }).await {
                            Some(v) => v,
                            _ => {
                                anyhow::bail!("no (global IP) remote address provided...");
                            }
                        };

                    if let Some(Ok((len, peer))) = udp.recv_from(&mut buf).timeout(Duration::from_millis(250)).await {
                        if ! addrs.contains(&peer) {
                            continue;
                        }

                        if let Ok(msg) = dns::Message::from_vec(&buf[..len]) {
                            for rd in msg.answers().iter().chain(msg.name_servers()).chain(msg.additionals()) {
                                let rdtype = rd.record_type();
                                if rdtype == 1u16.into() || rdtype == 28u16.into() {
                                    return Ok(true);
                                }
                            }
                        }
                    }
                }
                Ok(false)
            }

            ResetFromTcp => {
                let addrs = self.data.addrs().await;
                if addrs.is_empty() {
                    anyhow::bail!("no (global IP) remote address provided...");
                }

                let mut tcp = tcp_race_connect(&addrs).await?;

                let msg = Self::_gen_dns_query(&domain, 1, 1)?; // IN(1) A(1)
                let wire = msg.to_vec()?;
                let wire_len = wire.len();
                if wire_len > u16::MAX as usize {
                    anyhow::bail!("unexpected dns::Message length large than 65535");
                }
                let wire_len = (wire_len as u16).to_be_bytes(); // to big-endian bytes
                let data: Vec<u8> = wire_len.into_iter().chain(wire.into_iter()).collect();
                tcp.write_all(&data).await?;

                let mut buf: [u8; 3] = [0, 0, 0];
                Ok(
                    if let Some(Ok(_)) = tcp.read_exact(&mut buf).timeout(Duration::from_millis(5000)).await {
                        false
                    } else {
                        true
                    }
                )
            },
            EmptySoaFromLocal => {
                let addr =
                    match self.data.select_addr().await {
                        Some(v) => v,
                        _ => {
                            anyhow::bail!("no (China IP) remote address provided...");
                        }
                    };

                let mut tcp = TcpStream::connect(addr).await?;

                let msg = Self::_gen_dns_query(&domain, 1, 6)?; // IN(1) SOA(6)
                let wire = msg.to_vec()?;
                let wire_len = wire.len();
                if wire_len > u16::MAX as usize {
                    anyhow::bail!("unexpected dns::Message large than 65535");
                }
                let wire_len = (wire_len as u16).to_be_bytes(); // to big-endian bytes
                let data: Vec<u8> = wire_len.into_iter().chain(wire.into_iter()).collect();
                tcp.write_all(&data).await?;

                let mut buf_len: [u8; 2] = [0, 0];
                if let Some(ret) = tcp.read_exact(&mut buf_len).timeout(Duration::from_millis(2000)).await {
                    ret?;
                } else {
                    anyhow::bail!("recv u16 len from Local DNS server: timed out (timeout=2s)");
                }

                let buf_len = u16::from_be_bytes(buf_len) as usize;
                let mut buf = vec![0u8; buf_len];
                if let Some(ret) = tcp.read_exact(&mut buf).timeout(Duration::from_millis(2000)).await {
                    ret?;
                } else {
                    anyhow::bail!("recv body from Local DNS server: timed out (timeout=2s)");
                }

                let resp = dns::Message::from_vec(&buf)?;

                let mut spoofed = true;
                for rd in resp.answers().iter().chain(resp.name_servers()).chain(resp.additionals()) {
                    if rd.dns_class() != 1u16.into() {
                        continue;
                    }
                    if rd.record_type() == 6u16.into() {
                        spoofed = false;
                        break;
                    }
                }
                Ok(spoofed)
            },
            ResponseIpFromRootNS => {
                todo!();
            },
            GfwList => {
                Ok(self.data.as_domain().unwrap().contains_async(domain).await)
            },
        }
    }
}

async fn tcp_race_connect(addrs: &[SocketAddr]) -> anyhow::Result<TcpStream> {
    let (send, recv) = smol::channel::bounded(1);
    for addr in addrs.iter().copied() {
        let send = send.clone();
        smolscale2::spawn(async move {
            let result = TcpStream::connect(addr).await;
            if let Ok(conn) = result {
                let _ = send.try_send(conn);
            }
        }).detach();
    }

    if let Some(conn) = recv.recv().timeout(Duration::from_secs(5)).await {
        Ok(conn?)
    } else {
        anyhow::bail!("connection timed out: {addrs:?}");
    }
}

