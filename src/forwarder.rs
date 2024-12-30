use crate::*;

#[derive(Clone, Debug)]
pub struct DNSForwarder {
    detector: Arc<DomainSpoofDetector>,
    listen: SocketAddr,
    local: SocketAddr, // e.g. plaintext UDP 53, your router/gateway IP, or HitDNS proxied DoH (recommened)
    global: SocketAddr, // recommended HitDNS proxied DoH. https://docs.rs/hitdns
}
impl DNSForwarder {
    pub fn builder() -> DNSForwarderBuilder {
        Default::default()
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let udp = UdpSocket::bind(self.listen).await.context("cannot bind UDP")?;
        let tcp = TcpListener::bind(self.listen).await.context("cannot bind TCP")?;

        smol::future::or(
            self.handle_udp(udp),
            self.handle_tcp(tcp)
        ).await
    }

    async fn handle_udp(&self, udp: UdpSocket) -> anyhow::Result<()> {
        let mut buf = vec![0u8; 65535];
        let mut wire: Vec<u8>;
        loop {
            let (len, peer) =
                udp.recv_from(&mut buf).await
                .context("cannot recvfrom udp socket")?;

            wire = buf[..len].to_vec();
            let udp = udp.clone();

            let detector = self.detector.clone();
            let local = self.local;
            let global = self.global;

            smolscale2::spawn(async move {
                let msg = dns::Message::from_vec(&wire).unwrap();
                let domain = msg.queries()[0].name().to_ascii();

                let is_spoofed = detector.detect(&domain).await.unwrap();
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
    async fn handle_tcp(&self, tcp: TcpListener) -> anyhow::Result<()> {
        loop {
            let (mut conn, peer) = tcp.accept().await?;

            let detector = self.detector.clone();
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

                    is_spoofed = detector.detect(&domain).await.unwrap();
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
    maybe_detect_method: Option<DomainSpoofDetectMethod>,
    maybe_detect_data: Option<DomainSpoofDetectData>,
    maybe_status_cache: Option<DomainStatusCache>,

    maybe_listen: Option<SocketAddr>,
    maybe_local: Option<SocketAddr>,
    maybe_global: Option<SocketAddr>,
}
impl DNSForwarderBuilder {
    pub fn new() -> Self {
        Default::default()
    }
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

        let method =
            match self.maybe_detect_method {
                Some(val) => val,
                _ => {
                    let best = DomainSpoofDetectMethod::best_dynamic();
                    log::warn!("No Detect Method provided, using the reasonable best method: ({:?})", &best.0);
                    self.maybe_detect_data = Some(best.1);
                    best.0
                }
            };

        let data =
            match self.maybe_detect_data {
                Some(val) => val,
                _ => {
                    anyhow::bail!("No Detect Data provided!");
                }
            };

        let cache =
            match self.maybe_status_cache {
                Some(val) => val,
                _ => {
                    log::warn!("No DomainStatusCache provided, using the empty one.");
                    DomainStatusCache::new()
                }
            };

        let detector = Arc::new(DomainSpoofDetector::new(method, data, Some(cache)).await?);
        Ok(DNSForwarder {
            detector,
            listen,
            local,
            global,
        })
    }

    pub fn status_cache(mut self, c: DomainStatusCache) -> Self {
        self.maybe_status_cache = Some(c);
        self
    }

    pub fn detect_method(mut self, m: DomainSpoofDetectMethod) -> Self {
        self.maybe_detect_method = Some(m);
        self
    }
    pub fn detect_data(mut self, d: DomainSpoofDetectData) -> Self {
        self.maybe_detect_data = Some(d);
        self
    }

    pub fn listen(mut self, l: SocketAddr) -> Self {
        self.maybe_listen = Some(l);
        self
    }
    pub fn local(mut self, ldns: SocketAddr) -> Self {
        self.maybe_local = Some(ldns);
        self
    }
    pub fn global(mut self, g: SocketAddr) -> Self {
        self.maybe_global = Some(g);
        self
    }
}
