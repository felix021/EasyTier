//! Shadowsocks Tunnel Connector (stub implementation)
//!
//! This module provides a placeholder for the shadowsocks tunnel connector.
//! The main shadowsocks functionality is in the gateway/shadowsocks_connector.rs
//! which handles TCP proxy routing.

use anyhow::Result;
use async_trait::async_trait;
use tracing::warn;

use crate::common::config::ShadowsocksEndpoint;
use crate::tunnel::{Tunnel, TunnelConnector, TunnelError, TunnelInfo};

/// Shadowsocks tunnel connector - placeholder for future implementation
pub struct ShadowsocksTunnelConnector {
    endpoint: ShadowsocksEndpoint,
    url: url::Url,
}

impl ShadowsocksTunnelConnector {
    /// Create a new Shadowsocks tunnel connector
    pub fn new(endpoint: ShadowsocksEndpoint) -> Self {
        let url = url::Url::parse(&format!(
            "ss://{}@{}#{}",
            endpoint.cipher,
            endpoint.server,
            endpoint.name
        )).unwrap();

        Self { endpoint, url }
    }

    /// Get the endpoint name
    pub fn endpoint_name(&self) -> &str {
        &self.endpoint.name
    }

    /// Get the server address (as string)
    pub fn server_addr(&self) -> &str {
        &self.endpoint.server
    }
}

impl std::fmt::Debug for ShadowsocksTunnelConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShadowsocksTunnelConnector")
            .field("endpoint_name", &self.endpoint.name)
            .field("server", &self.endpoint.server)
            .field("cipher", &self.endpoint.cipher)
            .finish()
    }
}

#[async_trait]
impl TunnelConnector for ShadowsocksTunnelConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        warn!("Shadowsocks tunnel connector is not fully implemented for peer connections");
        Err(TunnelError::InvalidProtocol(
            "Shadowsocks tunnel connector is only available for TCP proxy routing".to_string()
        ))
    }

    fn remote_url(&self) -> url::Url {
        self.url.clone()
    }
}

/// Shadowsocks tunnel wrapper - placeholder
pub struct ShadowsocksTunnel {
    _private: (),
}

impl Tunnel for ShadowsocksTunnel {
    fn split(&self) -> crate::tunnel::SplitTunnel {
        unimplemented!("Shadowsocks tunnel not implemented for peer connections")
    }

    fn info(&self) -> Option<TunnelInfo> {
        None
    }
}
