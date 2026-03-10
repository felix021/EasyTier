//! Shadowsocks Router
//!
//! Routes outbound traffic through Shadowsocks endpoints based on flexible routing rules.

use std::{
    collections::HashMap,
    net::IpAddr,
};

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

use crate::common::config::{ShadowsocksConfig, ShadowsocksEndpoint, ShadowsocksRuleType};

#[cfg(feature = "shadowsocks")]
use maxminddb::Reader;

/// CIDR matcher for IP-CIDR rules
#[derive(Debug, Clone)]
struct IpCidrMatcher {
    cidr: cidr::Ipv4Cidr,
    target: String,
}

impl IpCidrMatcher {
    pub fn new(cidr: cidr::Ipv4Cidr, target: String) -> Self {
        Self { cidr, target }
    }

    /// Check if an IP address matches this CIDR
    pub fn matches(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.cidr.contains(v4),
            IpAddr::V6(_) => false,
        }
    }

    pub fn target(&self) -> &str {
        &self.target
    }
}

/// GEOIP matcher for country-based routing
#[derive(Debug, Clone)]
struct GeoipMatcher {
    country_code: String,
    target: String,
}

impl GeoipMatcher {
    pub fn new(country_code: String, target: String) -> Self {
        Self { country_code, target }
    }

    pub fn country_code(&self) -> &str {
        &self.country_code
    }

    pub fn target(&self) -> &str {
        &self.target
    }
}

/// Router for Shadowsocks traffic
/// Routes outbound traffic through Shadowsocks endpoints based on flexible routing rules
pub struct ShadowsocksRouter {
    /// Endpoint connectors
    endpoints: HashMap<String, ShadowsocksEndpoint>,
    /// CIDR matchers for IP-CIDR rules (in order)
    cidr_matchers: Vec<IpCidrMatcher>,
    /// GEOIP matchers for country-based routing (in order)
    geoip_matchers: Vec<GeoipMatcher>,
    /// Fallback target (if configured)
    fallback_target: Option<String>,
    /// GEOIP reader for country lookups
    #[cfg(feature = "shadowsocks")]
    geoip_reader: Option<Reader<Vec<u8>>>,
}

impl ShadowsocksRouter {
    /// Create a new Shadowsocks router
    pub fn new(config: &ShadowsocksConfig) -> Result<Self> {
        // Build endpoint map
        let endpoints: HashMap<String, ShadowsocksEndpoint> = config
            .endpoints
            .iter()
            .map(|e| (e.name.clone(), e.clone()))
            .collect();

        // Build matchers from rules
        let mut cidr_matchers = Vec::new();
        let mut geoip_matchers = Vec::new();
        let mut fallback_target = None;

        for rule in &config.rules {
            match rule.rule_type {
                ShadowsocksRuleType::IpCidr => {
                    if let Ok(cidr) = rule.value.parse::<cidr::Ipv4Cidr>() {
                        cidr_matchers.push(IpCidrMatcher::new(cidr, rule.target.clone()));
                    } else {
                        warn!("Failed to parse CIDR in rule: {}", rule.value);
                    }
                }
                ShadowsocksRuleType::Geoip => {
                    geoip_matchers.push(GeoipMatcher::new(
                        rule.value.to_uppercase(),
                        rule.target.clone(),
                    ));
                }
                ShadowsocksRuleType::Fallback => {
                    fallback_target = Some(rule.target.clone());
                }
            }
        }

        // Initialize GEOIP reader if database path provided
        #[cfg(feature = "shadowsocks")]
        let geoip_reader = if let Some(db_path) = &config.geoip_database {
            match std::fs::read(db_path) {
                Ok(db_content) => match Reader::from_source(db_content) {
                    Ok(reader) => {
                        info!("Loaded GEOIP database from: {:?}", db_path);
                        Some(reader)
                    }
                    Err(e) => {
                        warn!("Failed to load GEOIP database: {}", e);
                        None
                    }
                },
                Err(e) => {
                    warn!("Failed to read GEOIP database file: {}", e);
                    None
                }
            }
        } else {
            None
        };

        info!(
            "Shadowsocks router initialized: {} endpoints, {} CIDR rules, {} GEOIP rules, fallback={:?}",
            endpoints.len(),
            cidr_matchers.len(),
            geoip_matchers.len(),
            fallback_target
        );

        Ok(Self {
            endpoints,
            cidr_matchers,
            geoip_matchers,
            fallback_target,
            #[cfg(feature = "shadowsocks")]
            geoip_reader,
        })
    }

    /// Route an IP address to determine the target endpoint
    /// Returns the endpoint name or None for DIRECT routing
    pub fn route(&self, ip: &IpAddr) -> Option<&str> {
        // Check CIDR rules first (in order)
        for matcher in &self.cidr_matchers {
            if matcher.matches(ip) {
                debug!("IP {} matched CIDR rule -> {}", ip, matcher.target());
                return Some(matcher.target());
            }
        }

        // Check GEOIP rules (in order)
        #[cfg(feature = "shadowsocks")]
        if let Some(reader) = &self.geoip_reader {
            if let Ok(country) = self.lookup_country(reader, ip) {
                for matcher in &self.geoip_matchers {
                    if matcher.country_code() == country {
                        debug!("IP {} matched GEOIP rule {} -> {}", ip, country, matcher.target());
                        return Some(matcher.target());
                    }
                }
            }
        }

        // Return fallback if configured
        if let Some(ref fallback) = self.fallback_target {
            debug!("IP {} using fallback -> {}", ip, fallback);
            return Some(fallback);
        }

        // No rules match, return None (DIRECT)
        None
    }

    /// Look up country code for an IP address
    #[cfg(feature = "shadowsocks")]
    fn lookup_country(&self, reader: &Reader<Vec<u8>>, ip: &IpAddr) -> Result<String> {
        use maxminddb::geoip2::Country;

        let result: Country = reader
            .lookup(*ip)
            .with_context(|| format!("GEOIP lookup failed for IP: {}", ip))?;

        let country_code = result
            .country
            .and_then(|c| c.iso_code)
            .unwrap_or("UNKNOWN")
            .to_string();

        Ok(country_code)
    }

    /// Get endpoint by name
    pub fn get_endpoint(&self, name: &str) -> Option<&ShadowsocksEndpoint> {
        self.endpoints.get(name)
    }

    /// Check if there are any configured endpoints
    pub fn has_endpoints(&self) -> bool {
        !self.endpoints.is_empty()
    }
}

impl std::fmt::Debug for ShadowsocksRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShadowsocksRouter")
            .field("endpoints_count", &self.endpoints.len())
            .field("cidr_matchers_count", &self.cidr_matchers.len())
            .field("geoip_matchers_count", &self.geoip_matchers.len())
            .field("fallback_target", &self.fallback_target)
            .finish()
    }
}
