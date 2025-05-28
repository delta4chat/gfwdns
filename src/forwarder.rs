use crate::*;

#[derive(Clone, Debug)]
pub struct DNSForwarder {
    detectors: Arc<Vec<DomainSpoofDetector>>,
    listen: SocketAddr,
    local: SocketAddr, // e.g. plaintext UDP 53, your router/gateway IP, or HitDNS proxied DoH (recommened)
    global: SocketAddr, // recommended HitDNS proxied DoH. https://docs.rs/hitdns
}
impl DNSForwarder {
    #[inline(always)]
    pub fn builder() -> DNSForwarderBuilder {
        Default::default()
    }

    #[inline(always)]
    pub async fn run(self) -> anyhow::Result<()> {
        let udp = UdpSocket::bind(self.listen).await.context("cannot bind UDP")?;
        let tcp = TcpListener::bind(self.listen).await.context("cannot bind TCP")?;

        futures_lite::future::or(
            self.handle_udp(udp),
            self.handle_tcp(tcp)
        ).await
    }

    #[inline(always)]
    async fn handle_udp(&self, udp: UdpSocket) -> anyhow::Result<()> {
        let mut buf = vec![0u8; 65535];
        let mut wire: Vec<u8>;
        loop {
            let (len, peer) =
                udp.recv_from(&mut buf).await
                .context("cannot recvfrom udp socket")?;

            wire = buf[..len].to_vec();
            let udp = udp.clone();

            let detectors = self.detectors.clone();
            let local = self.local;
            let global = self.global;

            smolscale2::spawn(async move {
                let msg = dns::Message::from_vec(&wire).unwrap();
                let domain = msg.queries()[0].name().to_ascii();

                let mut is_spoofed = None;
                for detector in detectors.iter() {
                    match detector.detect(&domain).await {
                        Ok(b) => {
                            is_spoofed = Some(b);
                            if b {
                                break;
                            }
                        },
                        Err(e) => {
                            log::warn!("cannot detect the domain {domain:?} is_spoofed: {e:?}");
                        }
                    }
                }

                let is_spoofed =
                    match is_spoofed {
                        Some(v) => v,
                        _ => {
                            panic!("unable to detect is_spoofed for domain {domain:?}!");
                        }
                    };

                let upstream =
                    if is_spoofed {
                        global
                    } else {
                        local
                    };

                let client =
                    UdpSocket::bind(
                        if upstream.is_ipv4() {
                            "0.0.0.0:0"
                        } else {
                            "[::]:0"
                        }
                    ).await.unwrap();

                client.connect(upstream).await.unwrap();
                client.send(&wire).await.unwrap();

                let mut resp = vec![0u8; 65535];
                let len = client.recv(&mut resp).timeout(Duration::from_secs(5)).await.unwrap().unwrap();

                udp.send_to(&resp[..len], peer).await.unwrap();
            }).detach();
        }
    }

    #[inline(always)]
    async fn handle_tcp(&self, tcp: TcpListener) -> anyhow::Result<()> {
        loop {
            let (mut conn, peer) = tcp.accept().await?;

            let detectors = self.detectors.clone();
            let local = self.local;
            let global = self.global;

            smolscale2::spawn(async move {
                let mut len_buf = [0u8; 2];
                let mut len;

                let mut msg_buf = vec![0u8; 65535];
                let mut msg;

                let mut buf: Vec<u8>;

                let mut domain;
                let mut is_spoofed;

                let mut local_client = None;
                let mut global_client = None;
                let mut client;
                loop {
                    conn.read_exact(&mut len_buf).await.unwrap();
                    len = u16::from_be_bytes(len_buf) as usize;

                    conn.read_exact(&mut msg_buf[..len]).await.unwrap();

                    msg = dns::Message::from_vec(&msg_buf[..len]).unwrap();
                    domain = msg.queries()[0].name().to_ascii();

                    is_spoofed = None;
                    for detector in detectors.iter() {
                        match detector.detect(&domain).await {
                            Ok(b) => {
                                is_spoofed = Some(b);
                                if b {
                                    break;
                                }
                            },
                            Err(e) => {
                                log::warn!("cannot detect the domain {domain:?} is_spoofed: {e:?}");
                            }
                        }
                    }

                    let is_spoofed =
                        match is_spoofed {
                            Some(v) => v,
                            _ => {
                                panic!("unable to detect is_spoofed for domain {domain:?}!");
                            }
                        };

                    client =
                        if is_spoofed {
                            if global_client.is_none() {
                                global_client = Some(TcpStream::connect(global).await.unwrap());
                            }
                            global_client.as_mut().unwrap()
                        } else {
                            if local_client.is_none() {
                                local_client = Some(TcpStream::connect(local).await.unwrap());
                            }
                            local_client.as_mut().unwrap()
                        };

                    buf =
                        len_buf.iter().copied()
                        .chain((&msg_buf[..len]).iter().copied())
                        .collect();

                    client.write_all(&buf).await.unwrap();

                    client.read_exact(&mut len_buf).await.unwrap();
                    len = u16::from_be_bytes(len_buf) as usize;
                    client.read_exact(&mut msg_buf[..len]).await.unwrap();

                    buf = 
                        len_buf.iter().copied()
                        .chain((&msg_buf[..len]).iter().copied())
                        .collect();

                    conn.write_all(&buf).await.unwrap();
                }
            }).detach();
        }
    }
}

#[derive(Debug, Default)]
pub struct DNSForwarderBuilder {
    detect_method_data_list: Vec<(DomainSpoofDetectMethod, DomainSpoofDetectData)>,

    maybe_status_cache: Option<DomainStatusCache>,

    maybe_listen: Option<SocketAddr>,
    maybe_local: Option<SocketAddr>,
    maybe_global: Option<SocketAddr>,
}
impl DNSForwarderBuilder {
    #[inline(always)]
    pub fn new() -> Self {
        Default::default()
    }

    #[inline(always)]
    pub async fn build(mut self) -> anyhow::Result<DNSForwarder> {
        let listen =
            match self.maybe_listen {
                Some(val) => val,
                _ => {
                    anyhow::bail!("no listen address provided!");
                }
            };

        let local =
            match self.maybe_local {
                Some(val) => val,
                _ => {
                    anyhow::bail!("no local (inside the GFW) DNS server address provided!");
                }
            };

        let global =
            match self.maybe_global {
                Some(val) => val,
                _ => {
                    anyhow::bail!("no global (outside the GFW) DNS server address provided!");
                }
            };

        if self.detect_method_data_list.is_empty() {
            let best_dynamic = DomainSpoofDetectMethod::best_dynamic();
            let gfwlist = DomainSpoofDetectMethod::gfwlist();
            let chinalist = DomainSpoofDetectMethod::chinalist();

            log::warn!("No Detect Method & Data provided, using the reasonable best dynamic method: {:?}", [&best_dynamic.0, &gfwlist.0, &chinalist.0]);

            self.detect_method_data_list.push(gfwlist);
            self.detect_method_data_list.push(chinalist);
            self.detect_method_data_list.push(best_dynamic);
        }

        let cache =
            match self.maybe_status_cache {
                Some(val) => val,
                _ => {
                    log::warn!("No DomainStatusCache provided, using the empty one.");
                    DomainStatusCache::new()
                }
            };

        let mut detectors = Vec::new();
        for (method, data) in self.detect_method_data_list.into_iter() {
            detectors.push(DomainSpoofDetector::new(method, data, Some(cache.clone())).await?);
        }
        let detectors = Arc::new(detectors);

        Ok(DNSForwarder {
            detectors,
            listen,
            local,
            global,
        })
    }

    #[inline(always)]
    pub fn status_cache(mut self, c: DomainStatusCache) -> Self {
        self.maybe_status_cache = Some(c);
        self
    }

    #[inline(always)]
    pub fn detect_method_data(mut self, m: DomainSpoofDetectMethod, d: DomainSpoofDetectData) -> Self {
        self.detect_method_data_list.push((m, d));
        self
    }

    #[inline(always)]
    pub fn listen(mut self, l: SocketAddr) -> Self {
        self.maybe_listen = Some(l);
        self
    }

    #[inline(always)]
    pub fn local(mut self, ldns: SocketAddr) -> Self {
        self.maybe_local = Some(ldns);
        self
    }

    #[inline(always)]
    pub fn global(mut self, g: SocketAddr) -> Self {
        self.maybe_global = Some(g);
        self
    }
}
