use futures::stream::{self, StreamExt};
use local_ip_address::local_ip;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use tokio::process::Command;
use tokio::sync::Mutex;

const MAX_CONCURRENT_HOSTS:   usize = 48;
const TCP_TIMEOUT:         Duration = Duration::from_millis(400);
const ARP_TIMEOUT:         Duration = Duration::from_millis(2000);
const VENDOR_MIN_INTERVAL: Duration = Duration::from_millis(1100);

#[derive(Debug, Clone, PartialEq)]
pub enum ScanState {
    Open,
    Closed,
}

use iced::Color;
use iced::widget::text::{Rich, Span};

impl ScanState {
    pub fn to_richtext<'a, Message>(&self) -> Rich<'a, (), Message> {
        let span = match self {
            // ScanState::Loading => Span::new("Loading").color(Color::from_rgb(0.5, 0.5, 0.5)),
            ScanState::Open   => Span::new("Open"  ).color(Color::from_rgb(0.0, 0.8, 0.0)),
            ScanState::Closed => Span::new("Closed").color(Color::from_rgb(0.8, 0.0, 0.0)),
        };
        Rich::with_spans([span])
    }
}

#[derive(Debug, Clone)]
pub struct Device {
    pub ip: String,
    pub icmp: ScanState,
    pub hostname: Option<String>,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub http: ScanState,
    pub https: ScanState,
}

impl Device {
    pub fn is_empty(&self) -> bool {
        self.icmp == ScanState::Closed ||
        self.hostname.is_none() ||
        self.mac.is_none() ||
        self.vendor.is_none() ||
        self.http == ScanState::Closed ||
        self.https == ScanState::Closed
    }
}

pub fn local_subnet_base() -> Option<String> {
    match local_ip().ok()? {
        IpAddr::V4(ip) => {
            let o = ip.octets();
            Some(format!("{}.{}.{}", o[0], o[1], o[2]))
        }
        IpAddr::V6(_) => None,
    }
}

pub async fn scan_subnet<F>(base: String, mut on_found: F)
where
    F: FnMut(Device),
{
    let hosts: Vec<Ipv4Addr> = (1..=254u8)
        .filter_map(|last| format!("{base}.{last}").parse().ok())
        .collect();

    let mut results = stream::iter(hosts)
        .map(scan_host)
        .buffer_unordered(MAX_CONCURRENT_HOSTS);

    while let Some(device) = results.next().await {
        on_found(device);
    }
}

async fn scan_host(ip: Ipv4Addr) -> Device {
    let ip_string = ip.to_string();

    let (icmp_up, (http_open, https_open), hostname) =
        tokio::join!(ping(&ip_string), check_ports(&ip_string), reverse_dns(ip),);

    let mac = get_mac(&ip_string).await;
    let vendor = match &mac {
        Some(mac) => get_vendor(mac).await,
        None => None,
    };

    Device {
        ip: ip_string,
        icmp:  if icmp_up    { ScanState::Open } else { ScanState::Closed },
        hostname,
        mac,
        vendor,
        http:  if http_open  { ScanState::Open } else { ScanState::Closed },
        https: if https_open { ScanState::Open } else { ScanState::Closed },
    }
}

async fn ping(ip: &str) -> bool {
    let mut cmd = Command::new("ping");

    #[cfg(target_os = "windows")]
    cmd.args(["-n", "1", "-w", "500", ip]);

    #[cfg(not(target_os = "windows"))]
    cmd.args(["-c", "1", "-W", "1", ip]);

    #[cfg(target_os = "windows")]
    {
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    matches!(cmd.output().await, Ok(output) if output.status.success())
}

async fn check_ports(ip: &str) -> (bool, bool) {
    tokio::join!(check_tcp_port(ip, 80), check_tcp_port(ip, 443))
}

async fn check_tcp_port(ip: &str, port: u16) -> bool {
    let addr = format!("{ip}:{port}");
    let connect = tokio::net::TcpStream::connect(addr);
    matches!(tokio::time::timeout(TCP_TIMEOUT, connect).await, Ok(Ok(_)))
}

async fn reverse_dns(ip: Ipv4Addr) -> Option<String> {
    let addr = IpAddr::V4(ip);

    let result = tokio::time::timeout(
        Duration::from_millis(600),
        tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&addr)),
    )
    .await
    .ok()?
    .ok()?;

    match result {
        Ok(name) if name != ip.to_string() => Some(name),
        _ => None,
    }
}

async fn get_mac(ip: &str) -> Option<String> {
    let mut cmd = Command::new("arp");

    #[cfg(target_os = "windows")]
    cmd.args(["-a", ip]);

    #[cfg(not(target_os = "windows"))]
    cmd.args(["-n", ip]);

    #[cfg(target_os = "windows")]
    {
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let output = tokio::time::timeout(ARP_TIMEOUT, cmd.output())
        .await
        .ok()?
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);

    text.split_whitespace()
        .find(|token| looks_like_mac(token))
        .map(|s| s.to_uppercase())
}

fn looks_like_mac(token: &str) -> bool {
    let parts: Vec<&str> = token.split(['-', ':']).collect();
    parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

static VENDOR_CACHE:        LazyLock<Mutex<HashMap<String, String>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
static LAST_VENDOR_REQUEST: LazyLock<Mutex<Option<Instant>>>         = LazyLock::new(|| Mutex::new(None));
static HTTP_CLIENT:         LazyLock<reqwest::Client>                = LazyLock::new(reqwest::Client::new);

async fn get_vendor(mac: &str) -> Option<String> {
    let oui = mac
        .splitn(4, [':', '-'])
        .take(3)
        .collect::<Vec<_>>()
        .join(":");
    if oui.len() < 8 {
        return None;
    }

    if let Some(cached) = VENDOR_CACHE.lock().await.get(&oui) {
        return Some(cached.clone());
    }

    // throttle all outbound requests to respect the 1(ish) req/sec api limit (free tier)
    {
        let mut last = LAST_VENDOR_REQUEST.lock().await;
        if let Some(prev) = *last {
            let elapsed = prev.elapsed();
            if elapsed < VENDOR_MIN_INTERVAL {
                tokio::time::sleep(VENDOR_MIN_INTERVAL - elapsed).await;
            }
        }
        *last = Some(Instant::now());
    }

    let url = format!("https://api.macvendors.com/{oui}");
    let resp = HTTP_CLIENT
        .get(&url)
        .timeout(Duration::from_secs(3))
        .send()
        .await
        .ok()?;

    if !resp.status().is_success() {
        return None;
    };

    let vendor = resp.text().await.ok()?;

    VENDOR_CACHE.lock().await.insert(oui, vendor.clone());
    Some(vendor)
}
