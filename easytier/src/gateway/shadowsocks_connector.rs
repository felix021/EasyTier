//! Shadowsocks Connector for TCP Proxy
//!
//! Provides a wrapper connector that routes outbound TCP traffic through Shadowsocks
//! endpoints based on configured routing rules.

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as AnyhowContext, Result};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::timeout;
use tracing::{debug, info, warn};

#[cfg(feature = "shadowsocks")]
use shadowsocks::{
    config::{ServerConfig, ServerType},
    relay::tcprelay::proxy_stream::ProxyClientStream,
    context::{Context, SharedContext},
    relay::socks5::Address,
    crypto::CipherKind,
};

use crate::common::error::Result as EasyTierResult;
use crate::common::global_ctx::{ArcGlobalCtx, GlobalCtx};
use crate::gateway::shadowsocks_router::ShadowsocksRouter;
use crate::gateway::CidrSet;
use crate::proto::api::instance::TcpProxyEntryTransportType;
use crate::tunnel::packet_def::PeerManagerHeader;

use super::tcp_proxy::{prepare_kernel_tcp_socket, NatDstConnector};

/// Shadowsocks-aware TCP connector that routes traffic based on rules
#[derive(Clone)]
pub struct ShadowsocksTcpConnector {
    global_ctx: ArcGlobalCtx,
}

impl ShadowsocksTcpConnector {
    pub fn new(global_ctx: ArcGlobalCtx) -> Self {
        Self { global_ctx }
    }

    /// Get the shadowsocks router from global context
    #[cfg(feature = "shadowsocks")]
    fn get_shadowsocks_router(&self) -> Option<Arc<ShadowsocksRouter>> {
        self.global_ctx.get_shadowsocks_router().cloned()
    }

    /// Route an IP address through shadowsocks if needed
    /// Returns the endpoint name if routing through shadowsocks, None for direct connection
    #[cfg(feature = "shadowsocks")]
    fn route_ip(&self, ip: &IpAddr) -> Option<String> {
        if let Some(router) = self.get_shadowsocks_router() {
            if let Some(endpoint_name) = router.route(ip) {
                if endpoint_name != "DIRECT" {
                    debug!("Routing IP {} through shadowsocks endpoint: {}", ip, endpoint_name);
                    return Some(endpoint_name.to_string());
                }
            }
        }
        None
    }

    /// Connect to destination, possibly through shadowsocks
    async fn connect_with_routing(
        &self,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> EasyTierResult<ShadowsocksTcpStream> {
        #[cfg(feature = "shadowsocks")]
        {
            // Check if we need to route through shadowsocks
            if let Some(endpoint_name) = self.route_ip(&dst.ip()) {
                return Ok(ShadowsocksTcpStream::Proxied(
                    self.connect_via_shadowsocks(endpoint_name, dst).await?
                ));
            }
        }

        // Direct connection
        Ok(ShadowsocksTcpStream::Direct(self.connect_direct(src, dst).await?))
    }

    /// Connect directly to destination
    async fn connect_direct(
        &self,
        _src: SocketAddr,
        dst: SocketAddr,
    ) -> EasyTierResult<TcpStream> {
        let socket = match TcpSocket::new_v4() {
            Ok(s) => s,
            Err(error) => {
                warn!(%error, "create v4 socket failed");
                return Err(error.into());
            }
        };

        let stream = timeout(Duration::from_secs(10), socket.connect(dst))
            .await?
            .context(format!("connect to nat dst failed: {:?}", dst))?;

        prepare_kernel_tcp_socket(&stream)?;

        Ok(stream)
    }

    /// Connect through a shadowsocks endpoint
    #[cfg(feature = "shadowsocks")]
    async fn connect_via_shadowsocks(
        &self,
        endpoint_name: String,
        dst: SocketAddr,
    ) -> EasyTierResult<ProxyClientStream<shadowsocks::net::TcpStream>> {
        let Some(router) = self.get_shadowsocks_router() else {
            warn!("Shadowsocks router not available");
            return Err(anyhow::anyhow!("Shadowsocks router not available").into());
        };

        let Some(endpoint) = router.get_endpoint(&endpoint_name) else {
            warn!("Shadowsocks endpoint not found: {}", endpoint_name);
            return Err(anyhow::anyhow!("Shadowsocks endpoint not found: {}", endpoint_name).into());
        };

        debug!(
            "Connecting to {} via Shadowsocks server: {} ({})",
            dst, endpoint.name, endpoint.server
        );

        // Parse server address from string
        let server_addr: SocketAddr = endpoint.server.parse()
            .map_err(|e| anyhow::anyhow!("Invalid server address '{}': {}", endpoint.server, e))?;

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
        let ctx = Context::new(ServerType::Local);
        let context = SharedContext::new(ctx);

        // Build target address from destination
        let target_addr = match dst.ip() {
            IpAddr::V4(v4) => Address::SocketAddress(SocketAddr::new(v4.into(), dst.port())),
            IpAddr::V6(v6) => Address::SocketAddress(SocketAddr::new(v6.into(), dst.port())),
        };

        // Connect to the shadowsocks proxy
        let proxy_stream: ProxyClientStream<shadowsocks::net::TcpStream> = timeout(Duration::from_secs(10),
            ProxyClientStream::connect(context, &server_config, target_addr)
        )
        .await
        .context("Shadowsocks connection timeout")?
        .context(format!("Shadowsocks connection failed to {}", endpoint.server))?;

        info!(
            "Connected to {} via Shadowsocks endpoint: {}",
            dst, endpoint_name
        );

        Ok(proxy_stream)
    }
}

/// TCP stream that can be either direct or proxied through shadowsocks
pub enum ShadowsocksTcpStream {
    Direct(TcpStream),
    #[cfg(feature = "shadowsocks")]
    Proxied(ProxyClientStream<shadowsocks::net::TcpStream>),
}

impl AsyncRead for ShadowsocksTcpStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            ShadowsocksTcpStream::Direct(stream) => {
                std::pin::Pin::new(stream).poll_read(cx, buf)
            }
            #[cfg(feature = "shadowsocks")]
            ShadowsocksTcpStream::Proxied(stream) => {
                std::pin::Pin::new(stream).poll_read(cx, buf)
            }
        }
    }
}

impl AsyncWrite for ShadowsocksTcpStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        match self.get_mut() {
            ShadowsocksTcpStream::Direct(stream) => {
                std::pin::Pin::new(stream).poll_write(cx, buf)
            }
            #[cfg(feature = "shadowsocks")]
            ShadowsocksTcpStream::Proxied(stream) => {
                std::pin::Pin::new(stream).poll_write(cx, buf)
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            ShadowsocksTcpStream::Direct(stream) => {
                std::pin::Pin::new(stream).poll_flush(cx)
            }
            #[cfg(feature = "shadowsocks")]
            ShadowsocksTcpStream::Proxied(stream) => {
                std::pin::Pin::new(stream).poll_flush(cx)
            }
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            ShadowsocksTcpStream::Direct(stream) => {
                std::pin::Pin::new(stream).poll_shutdown(cx)
            }
            #[cfg(feature = "shadowsocks")]
            ShadowsocksTcpStream::Proxied(stream) => {
                std::pin::Pin::new(stream).poll_shutdown(cx)
            }
        }
    }
}

#[async_trait::async_trait]
impl NatDstConnector for ShadowsocksTcpConnector {
    type DstStream = ShadowsocksTcpStream;

    async fn connect(&self, src: SocketAddr, dst: SocketAddr) -> EasyTierResult<Self::DstStream> {
        self.connect_with_routing(src, dst).await
    }

    fn check_packet_from_peer_fast(&self, cidr_set: &CidrSet, global_ctx: &GlobalCtx) -> bool {
        // Same logic as NatDstTcpConnector
        !cidr_set.is_empty() || global_ctx.enable_exit_node() || global_ctx.no_tun()
    }

    fn check_packet_from_peer(
        &self,
        cidr_set: &CidrSet,
        global_ctx: &GlobalCtx,
        hdr: &PeerManagerHeader,
        ipv4: &std::net::Ipv4Addr,
        real_dst_ip: &mut std::net::Ipv4Addr,
    ) -> bool {
        // Same logic as NatDstTcpConnector
        let is_exit_node = hdr.is_exit_node();

        if !(cidr_set.contains_v4(*ipv4, real_dst_ip)
            || is_exit_node
            || global_ctx.no_tun()
                && Some(*ipv4) == global_ctx.get_ipv4().as_ref().map(|x| x.address()))
        {
            return false;
        }

        true
    }

    fn transport_type(&self) -> TcpProxyEntryTransportType {
        TcpProxyEntryTransportType::Tcp
    }
}
