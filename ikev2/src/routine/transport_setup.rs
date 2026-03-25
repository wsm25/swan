use anyhow::{Context, Result};
use std::net::SocketAddr;

use crate::{IKEV2_NAT_T_PORT, UdpConn};

use super::{IkeSaState, Ikev2Routine, TransportSetup};

impl Ikev2Routine {
    pub(super) fn setup_transport(&mut self, udp_conn: &dyn UdpConn) -> Result<()> {
        self.sa.reset();
        self.sa.state = IkeSaState::Starting;
        let local_addr = udp_conn.local_addr().context("query local UDP socket address")?;
        let peer_addr = match &self.config.peer {
            crate::config::PeerAddress::Ip(addr) => *addr,
            crate::config::PeerAddress::Domain(_) => SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                IKEV2_NAT_T_PORT,
            ),
        };
        let local_addr = SocketAddr::new(local_addr.ip(), IKEV2_NAT_T_PORT);
        self.transport = Some(TransportSetup { local_addr, peer_addr, natt_active: true });
        Ok(())
    }

    pub(super) fn update_transport_on_inbound(&mut self, src: SocketAddr, dst: SocketAddr) {
        if let Some(transport) = self.transport.as_mut() {
            transport.peer_addr = src;
            transport.local_addr = SocketAddr::new(dst.ip(), IKEV2_NAT_T_PORT);
        }
    }
}
