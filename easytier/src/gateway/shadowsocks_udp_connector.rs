//! Shadowsocks Connector for UDP Proxy
//!
//! Provides a wrapper that routes outbound UDP traffic through Shadowsocks
//! endpoints based on configured routing rules.

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, info, warn};

#[cfg(feature = "shadowsocks")]
use shadowsocks::{
    config::{ServerConfig, ServerType},
    relay::udprelay::proxy_socket::ProxySocket,
    relay::socks5::Address,
    context::{Context as SsContext, SharedContext},
    crypto::CipherKind,
    net::UdpSocket as ShadowUdpSocket,
};

use crate::common::error::Result as EasyTierResult;
use crate::common::global_ctx::ArcGlobalCtx;
use crate::gateway::shadowsocks_router::ShadowsocksRouter;

/// Shadowsocks-aware UDP socket that can be either direct or proxied
pub enum ShadowsocksUdpSocket {
    Direct(UdpSocket),
    #[cfg(feature = "shadowsocks")]
    Proxied {
        socket: ProxySocket<ShadowUdpSocket>,
        endpoint_name: String,
    },
}

impl ShadowsocksUdpSocket {
    /// Create a direct UDP socket
    pub async fn direct() -> EasyTierResult<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        Ok(Self::Direct(socket))
    }

    /// Create a proxied UDP socket through shadowsocks
    #[cfg(feature = "shadowsocks")]
    pub async fn proxied(
        global_ctx: ArcGlobalCtx,
        endpoint_name: &str,
    ) -> EasyTierResult<Self> {
        let Some(router) = global_ctx.get_shadowsocks_router() else {
            warn!("Shadowsocks router not available");
            return Err(anyhow::anyhow!("Shadowsocks router not available").into());
        };

        let Some(endpoint) = router.get_endpoint(endpoint_name) else {
            warn!("Shadowsocks endpoint not found: {}", endpoint_name);
            return Err(anyhow::anyhow!("Shadowsocks endpoint not found: {}", endpoint_name).into());
        };

        debug!(
            "Creating proxied UDP socket for Shadowsocks server: {} ({})",
            endpoint.name, endpoint.server
        );

        // Resolve server address (support both IP and domain name)
        let server_addr: SocketAddr = tokio::net::lookup_host(&endpoint.server)
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("Failed to resolve server address: {}", endpoint.server))?;

        // Parse cipher kind using FromStr
        let method = CipherKind::from_str(&endpoint.cipher)
            .map_err(|e| anyhow::anyhow!("Invalid cipher '{}': {}", endpoint.cipher, e))?;

        // Create Shadowsocks server config
        let server_config = ServerConfig::new(
            server_addr,
            endpoint.password.clone(),
            method,
        )
        .map_err(|e| anyhow::anyhow!("Invalid server config: {}", e))?;

        // Create shared context
        let ctx = SsContext::new(ServerType::Local);
        let context = SharedContext::new(ctx);

        // Connect to the shadowsocks proxy
        let connect_result = timeout(
            Duration::from_secs(10),
            ProxySocket::connect(context, &server_config)
        )
        .await
        .map_err(|e| anyhow::anyhow!("Shadowsocks UDP connection timeout: {}", e))?;

        let proxy_socket: ProxySocket<ShadowUdpSocket> = connect_result
            .map_err(|e| anyhow::anyhow!("Shadowsocks UDP connection failed to {}: {}", endpoint.server, e))?;

        info!(
            "Created proxied UDP socket via Shadowsocks endpoint: {}",
            endpoint_name
        );

        Ok(Self::Proxied {
            socket: proxy_socket,
            endpoint_name: endpoint_name.to_string(),
        })
    }

    /// Send UDP packet to destination
    /// For proxied sockets, the target address is embedded in the shadowsocks packet
    pub async fn send_to(&self, buf: &[u8], dst: SocketAddr) -> EasyTierResult<usize> {
        match self {
            Self::Direct(socket) => {
                socket.send_to(buf, dst).await.map_err(Into::into)
            }
            #[cfg(feature = "shadowsocks")]
            Self::Proxied { socket, .. } => {
                let target_addr = match dst.ip() {
                    IpAddr::V4(v4) => Address::SocketAddress(SocketAddr::new(v4.into(), dst.port())),
                    IpAddr::V6(v6) => Address::SocketAddress(SocketAddr::new(v6.into(), dst.port())),
                };

                let send_result: Result<usize, shadowsocks::relay::udprelay::proxy_socket::ProxySocketError> =
                    socket.send(&target_addr, buf).await;
                send_result
                    .map_err(|e| anyhow::anyhow!("Shadowsocks UDP send failed: {}", e).into())
            }
        }
    }

    /// Receive UDP packet from socket
    /// For proxied sockets, returns the target address from the shadowsocks packet
    pub async fn recv_from(&self, buf: &mut [u8]) -> EasyTierResult<(usize, SocketAddr)> {
        match self {
            Self::Direct(socket) => {
                socket.recv_from(buf).await.map_err(Into::into)
            }
            #[cfg(feature = "shadowsocks")]
            Self::Proxied { socket, .. } => {
                let recv_result = socket.recv(buf).await
                    .map_err(|e: shadowsocks::relay::udprelay::proxy_socket::ProxySocketError| {
                        anyhow::anyhow!("Shadowsocks UDP recv failed: {}", e)
                    })?;
                let (size, target_addr, _) = recv_result;

                // Convert Address back to SocketAddr
                let socket_addr = match target_addr {
                    Address::SocketAddress(sa) => sa,
                    Address::DomainNameAddress(domain, port) => {
                        // Resolve domain name
                        tokio::net::lookup_host(format!("{}:{}", domain, port))
                            .await?
                            .next()
                            .ok_or_else(|| anyhow::anyhow!("Failed to resolve domain: {}", domain))?
                    }
                };

                Ok((size, socket_addr))
            }
        }
    }
}

/// Shadowsocks-aware UDP connector that routes traffic based on rules
#[derive(Clone)]
pub struct ShadowsocksUdpConnector {
    global_ctx: ArcGlobalCtx,
}

impl ShadowsocksUdpConnector {
    pub fn new(global_ctx: ArcGlobalCtx) -> Self {
        Self { global_ctx }
    }

    /// Get the shadowsocks router from global context
    #[cfg(feature = "shadowsocks")]
    fn get_shadowsocks_router(&self) -> Option<Arc<ShadowsocksRouter>> {
        self.global_ctx.get_shadowsocks_router().cloned()
    }

    /// Route an IP address to determine the target endpoint
    /// Returns the endpoint name if routing through shadowsocks, None for direct connection
    #[cfg(feature = "shadowsocks")]
    fn route_ip(&self, ip: &IpAddr) -> Option<String> {
        if let Some(router) = self.get_shadowsocks_router() {
            if let Some(endpoint_name) = router.route(ip) {
                if endpoint_name != "DIRECT" {
                    debug!("Routing UDP {} through shadowsocks endpoint: {}", ip, endpoint_name);
                    return Some(endpoint_name.to_string());
                }
            }
        }
        None
    }

    /// Get the appropriate UDP socket for the destination
    /// Returns direct socket for DIRECT routing, proxied socket for shadowsocks routing
    pub async fn get_socket_for_dest(&self, dst: SocketAddr) -> EasyTierResult<ShadowsocksUdpSocket> {
        #[cfg(feature = "shadowsocks")]
        {
            // Check if we need to route through shadowsocks
            if let Some(endpoint_name) = self.route_ip(&dst.ip()) {
                return Ok(ShadowsocksUdpSocket::proxied(
                    self.global_ctx.clone(),
                    &endpoint_name,
                ).await?);
            }
        }

        // Direct socket
        Ok(ShadowsocksUdpSocket::direct().await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connector_clone() {
        // Just verify the connector can be cloned (required for the trait)
        // Actual functionality testing requires a running GlobalCtx
    }
}
