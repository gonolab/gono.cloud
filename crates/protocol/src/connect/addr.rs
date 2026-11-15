//! Direct addresses that no peer can reach (protocol 7.1).

use std::net::{IpAddr, SocketAddr};

/// Whether `addr` may be published and dialed as a direct address. Refused: the unspecified
/// address, loopback, multicast, the IPv4 broadcast address and port 0, also in their
/// IPv4-mapped IPv6 forms. Private and link-local addresses pass, because two devices on one LAN
/// may reach each other through the remote endpoint.
///
/// iroh filters none of these, so without this check a compromised server could make a device
/// send probes to its own loopback (Input Show's LAN endpoint) or to multicast groups.
pub fn is_dialable(addr: &SocketAddr) -> bool {
    if addr.port() == 0 {
        return false;
    }
    match addr.ip().to_canonical() {
        IpAddr::V4(ip) => {
            !(ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.is_broadcast())
        }
        IpAddr::V6(ip) => !(ip.is_unspecified() || ip.is_loopback() || ip.is_multicast()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dialable(addr: &str) -> bool {
        is_dialable(&addr.parse().unwrap())
    }

    #[test]
    fn public_private_and_link_local_addresses_pass() {
        for addr in [
            "198.51.100.7:40211",
            "192.168.1.20:24850",
            "10.0.0.2:1",
            "169.254.10.1:5000",
            "[2001:db8::1]:51820",
            "[fe80::1]:51820",
            "[fd00::2]:51820",
            "[::ffff:192.0.2.10]:51820",
        ] {
            assert!(dialable(addr), "{addr}");
        }
    }

    #[test]
    fn addresses_no_peer_can_reach_are_refused() {
        for addr in [
            "0.0.0.0:24850",
            "127.0.0.1:24850",
            "127.8.9.10:24850",
            "224.0.0.251:5353",
            "239.1.2.3:4000",
            "255.255.255.255:9",
            "192.0.2.10:0",
            "[::]:24850",
            "[::1]:24850",
            "[ff02::fb]:5353",
            "[::ffff:127.0.0.1]:24850",
            "[::ffff:0.0.0.0]:24850",
            "[::ffff:224.0.0.251]:5353",
            "[2001:db8::1]:0",
        ] {
            assert!(!dialable(addr), "{addr}");
        }
    }
}
