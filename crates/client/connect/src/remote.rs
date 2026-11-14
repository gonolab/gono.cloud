//! The product API of plan 3.3: the endpoint and the control channel together.
//!
//! - [`Remote::start`] binds the endpoint as in plan 3.5, with the server's relay, and opens
//!   the control channel; its events go to the receiver it returns.
//! - [`Remote::connect`] asks the server to connect (`connect`, recorded and announced to the
//!   target) and dials the device by its key. [`Remote::connect_for_pairing`] does the same for
//!   the approver of a pending pairing request (protocol 8.2).
//! - [`Remote::accept`] hands out incoming connections. Whether a peer may do anything is the
//!   product's decision: its key must be in the product's trust list (threat model C8).
//! - [`Remote::network_change`] forwards the platform's network events (plan 3.3; HarmonyOS
//!   and Android need it).

use gono_protocol::connect::{DeviceId, Discovery, message::Purpose};
use iroh::{
    Endpoint, EndpointAddr, RelayUrl, SecretKey,
    endpoint::{Accept, Connection},
};
use tokio::sync::mpsc;

use crate::{
    ChannelEvent, ChannelOptions, ControlChannel, ControlLookup, Credentials, Error, Result,
    endpoint::{self, Dns, EndpointOptions},
};

/// What [`Remote::start`] needs.
#[derive(Debug, Clone)]
pub struct RemoteOptions {
    /// The server's discovery document.
    pub discovery: Discovery,
    /// The device's credential.
    pub credentials: Credentials,
    /// The device's key.
    pub key: SecretKey,
    /// The ALPNs the device accepts, which it also lists as its services.
    pub alpns: Vec<Vec<u8>>,
    /// The UDP port; 0 picks a free one.
    pub port: u16,
    /// Name resolution.
    pub dns: Dns,
    /// The channel's options beyond the credential: cursor, version, settings, features.
    pub channel: Option<ChannelOptions>,
}

/// See the module documentation.
#[derive(Debug, Clone)]
pub struct Remote {
    endpoint: Endpoint,
    channel: ControlChannel,
    lookup: ControlLookup,
}

impl Remote {
    /// Opens the control channel and binds the endpoint.
    pub async fn start(options: RemoteOptions) -> Result<(Self, mpsc::Receiver<ChannelEvent>)> {
        let relay_url: RelayUrl = options
            .discovery
            .relay_url
            .parse()
            .map_err(|_| Error::Url(options.discovery.relay_url.clone()))?;
        let channel_options = options.channel.clone().unwrap_or_else(|| {
            ChannelOptions::new(
                options.discovery.clone(),
                options.credentials.clone(),
                options.key.clone(),
            )
        });
        let (channel, events) = ControlChannel::start(channel_options);
        let lookup = ControlLookup::new(channel.clone());
        let endpoint = endpoint::bind(
            EndpointOptions {
                secret_key: options.key,
                relay_url,
                alpns: options.alpns,
                port: options.port,
                dns: options.dns,
            },
            lookup.clone(),
        )
        .await?;
        Ok((
            Self {
                endpoint,
                channel,
                lookup,
            },
            events,
        ))
    }

    /// The iroh endpoint.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// The control channel.
    pub fn channel(&self) -> &ControlChannel {
        &self.channel
    }

    /// Connects to `device` for `alpn` (protocol 7.2).
    pub async fn connect(&self, device: DeviceId, alpn: &[u8]) -> Result<Connection> {
        self.dial(device, alpn, Purpose::Session, None).await
    }

    /// Connects to the new device of the pending pairing request `request_id` (protocol 8.2,
    /// step 2).
    pub async fn connect_for_pairing(
        &self,
        device: DeviceId,
        alpn: &[u8],
        request_id: String,
    ) -> Result<Connection> {
        self.dial(device, alpn, Purpose::Pair, Some(request_id))
            .await
    }

    async fn dial(
        &self,
        device: DeviceId,
        alpn: &[u8],
        purpose: Purpose,
        request_id: Option<String>,
    ) -> Result<Connection> {
        let service = String::from_utf8_lossy(alpn).into_owned();
        let result = self
            .channel
            .connect_to(device, &service, purpose, request_id)
            .await?;
        self.lookup.remember(&result);
        let info = crate::lookup::info(&result);
        let addr = EndpointAddr::from_parts(device.0, info.data.addrs().cloned());
        self.endpoint
            .connect(addr, alpn)
            .await
            .map_err(|err| Error::Connect(err.to_string()))
    }

    /// The next incoming connection attempt.
    pub fn accept(&self) -> Accept<'_> {
        self.endpoint.accept()
    }

    /// Tells the endpoint that the network changed.
    pub async fn network_change(&self) {
        self.endpoint.network_change().await;
    }

    /// Closes the endpoint. The control channel ends when its last handle is dropped.
    pub async fn close(self) {
        self.endpoint.close().await;
    }
}
