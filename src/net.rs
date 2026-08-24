use std::net::{UdpSocket, Ipv4Addr, IpAddr};
use std::sync::LazyLock;

pub static LOCAL_IP: LazyLock<Option<Ipv4Addr>> = LazyLock::new(local_ip_addr);

fn local_ip_addr() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:53").ok()?;

    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(_) => None,
    }
}

// returns an Iced rich text of the current IP
// address, where the subnet mask part of the IP
// is highlighted in blue
pub fn identity_string() -> Option<String> {
    Some(String::new())
    // this function is a stub and i need to water
    // that stub untill it grows, which will probably
    // mean having a dropdown for each network interface
}