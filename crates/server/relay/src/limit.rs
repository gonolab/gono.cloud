//! The rate at which the relay reads from a device connection, by the device's [`Tier`].
//!
//! iroh-relay's own server limits every connection to one rate, which it applies to the TCP
//! stream before the relay handshake has said which device is connecting. Here the limit is
//! chosen per connection once the handshake proved the device, and applied to the frames of
//! the relay protocol with iroh-relay's [`Bucket`], which it exports for this case.

use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
    time::Duration,
};

use anyhow::anyhow;
use bytes::Bytes;
use futures_util::{Sink, Stream};
use gono_server_core::config::RelayConfig;
use iroh_relay::{
    protos::streams::StreamError,
    server::{
        Metrics,
        streams::{Bucket, InvalidBucketConfig},
    },
};

use crate::Tier;

/// How often a bucket refills, as iroh-relay's own rate limit does: tokio's timers resolve
/// milliseconds, and a tenth of a second keeps the rate smooth.
const REFILL_PERIOD: Duration = Duration::from_millis(100);

/// A rate in bytes per second, with the largest burst read at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Rate {
    bytes_per_second: u32,
    burst_bytes: u32,
}

impl Rate {
    /// Checks that a bucket can meter the rate; `key` names the setting in the error.
    fn new(bytes_per_second: u32, burst_bytes: u32, key: &str) -> anyhow::Result<Self> {
        let rate = Self {
            bytes_per_second,
            burst_bytes,
        };
        rate.bucket().map_err(|err| {
            anyhow!(
                "{key}: the relay cannot meter {bytes_per_second} bytes per second in bursts \
                 of {burst_bytes} bytes ({err}); it needs at least 10 bytes per second"
            )
        })?;
        Ok(rate)
    }

    /// A full bucket of this rate.
    fn bucket(self) -> Result<Bucket, InvalidBucketConfig> {
        Bucket::new(
            i64::from(self.burst_bytes),
            i64::from(self.bytes_per_second),
            REFILL_PERIOD,
        )
    }
}

/// The rate of each tier, from the `[relay]` table.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    /// `relay.limited_bytes_per_sec` and `relay.limited_burst_bytes`.
    limited: Rate,
    /// `relay.max_client_bytes_per_sec` and `relay.max_client_burst_bytes`; unlimited when
    /// unset.
    full: Option<Rate>,
}

impl Limits {
    /// The limits of `config`. Fails when a rate cannot be metered, which validation lets
    /// through only for `relay.max_client_bytes_per_sec` below 10.
    pub(crate) fn from_config(config: &RelayConfig) -> anyhow::Result<Self> {
        // 0 means unset, as it always did: validation refuses it.
        let full = match config.max_client_bytes_per_sec.filter(|rate| *rate > 0) {
            Some(rate) => {
                // Without a burst, iroh-relay allows a tenth of the rate.
                let burst = config
                    .max_client_burst_bytes
                    .filter(|burst| *burst > 0)
                    .unwrap_or(rate / 10);
                Some(Rate::new(rate, burst, "relay.max_client_bytes_per_sec")?)
            }
            None => None,
        };
        let limited = Rate::new(
            config.limited_bytes_per_sec,
            config.limited_burst_bytes,
            "relay.limited_bytes_per_sec",
        )?;
        Ok(Self { limited, full })
    }

    /// A full bucket for a new connection at `tier`, or `None` when the tier is unlimited.
    pub(crate) fn bucket(&self, tier: Tier) -> Result<Option<Bucket>, InvalidBucketConfig> {
        let rate = match tier {
            Tier::Limited => Some(self.limited),
            Tier::Full => self.full,
        };
        rate.map(Rate::bucket).transpose()
    }
}

/// The frames a device sends, read no faster than its bucket allows; what the relay sends to
/// it passes unthrottled, as with iroh-relay's own limit.
///
/// Each frame is taken from the bucket once it is read. A frame that empties the bucket is
/// still delivered, and the next read waits until the bucket has refilled: while it waits the
/// relay reads nothing from the connection, so TCP pushes back on the device.
#[derive(Debug)]
pub(crate) struct Throttled<S> {
    inner: S,
    bucket: Option<Bucket>,
    /// Set while the bucket refills.
    refilled: Option<Pin<Box<tokio::time::Sleep>>>,
    /// Whether this connection was held back yet, for `conns_rx_ratelimited_total`.
    held_back: bool,
    metrics: Arc<Metrics>,
}

impl<S> Throttled<S> {
    /// Reads `inner` at the rate of `bucket`, or as fast as it comes without one.
    pub(crate) fn new(inner: S, bucket: Option<Bucket>, metrics: Arc<Metrics>) -> Self {
        Self {
            inner,
            bucket,
            refilled: None,
            held_back: false,
            metrics,
        }
    }

    /// Counts a frame of `bytes` that emptied the bucket, as iroh-relay's own limit does.
    fn record_held_back(&mut self, bytes: usize) {
        self.metrics
            .bytes_rx_ratelimited_total
            .inc_by(u64::try_from(bytes).unwrap_or(u64::MAX));
        if !self.held_back {
            self.held_back = true;
            self.metrics.conns_rx_ratelimited_total.inc();
        }
    }
}

impl<S> Stream for Throttled<S>
where
    S: Stream<Item = Result<Bytes, StreamError>> + Unpin,
{
    type Item = Result<Bytes, StreamError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        if this.bucket.is_none() {
            return Pin::new(&mut this.inner).poll_next(cx);
        }
        if let Some(refilled) = &mut this.refilled {
            ready!(refilled.as_mut().poll(cx));
            this.refilled = None;
        }
        let item = ready!(Pin::new(&mut this.inner).poll_next(cx));
        if let Some(Ok(frame)) = &item
            && let Some(bucket) = &mut this.bucket
            && let Err(refilled_at) = bucket.consume(frame.len())
        {
            let bytes = frame.len();
            this.record_held_back(bytes);
            this.refilled = Some(Box::pin(tokio::time::sleep_until(refilled_at)));
        }
        Poll::Ready(item)
    }
}

impl<S> Sink<Bytes> for Throttled<S>
where
    S: Sink<Bytes, Error = StreamError> + Unpin,
{
    type Error = StreamError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        Pin::new(&mut self.inner).start_send(item)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use futures_util::{StreamExt as _, stream};

    use super::*;

    fn config(limited: u32, burst: u32, full: Option<u32>) -> RelayConfig {
        RelayConfig {
            limited_bytes_per_sec: limited,
            limited_burst_bytes: burst,
            max_client_bytes_per_sec: full,
            ..RelayConfig::default()
        }
    }

    /// Frames of `size` bytes, `count` of them.
    fn frames(count: usize, size: usize) -> impl Stream<Item = Result<Bytes, StreamError>> + Unpin {
        stream::iter((0..count).map(move |_| Ok(Bytes::from(vec![0; size]))))
    }

    #[test]
    fn each_tier_gets_its_rate() {
        let limits = Limits::from_config(&config(16_384, 32_768, None)).unwrap();
        assert!(limits.bucket(Tier::Limited).unwrap().is_some());
        assert!(limits.bucket(Tier::Full).unwrap().is_none(), "unlimited");

        let limits = Limits::from_config(&config(16_384, 32_768, Some(1_000_000))).unwrap();
        assert!(limits.bucket(Tier::Full).unwrap().is_some());
    }

    #[test]
    fn rates_too_low_to_meter_stop_the_start() {
        let err = Limits::from_config(&config(5, 32_768, None)).unwrap_err();
        assert!(
            err.to_string().contains("relay.limited_bytes_per_sec"),
            "{err}"
        );
        // Without a burst, a tenth of the rate is none at all.
        let err = Limits::from_config(&config(16_384, 32_768, Some(9))).unwrap_err();
        assert!(
            err.to_string().contains("relay.max_client_bytes_per_sec"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn frames_beyond_the_burst_come_at_the_rate() {
        let metrics = Arc::new(Metrics::default());
        // 10 000 bytes per second in bursts of 2 000: 20 frames of 500 bytes are 10 000 bytes,
        // of which the burst takes 2 000 at once, so the rest takes 0.8 s.
        let bucket = Rate::new(10_000, 2_000, "test").unwrap().bucket().unwrap();
        let mut throttled = Throttled::new(frames(20, 500), Some(bucket), metrics.clone());
        let start = Instant::now();
        let mut read = 0;
        while let Some(frame) = throttled.next().await {
            read += frame.unwrap().len();
        }
        let elapsed = start.elapsed();
        assert_eq!(read, 10_000);
        assert!(elapsed >= Duration::from_millis(700), "{elapsed:?}");
        assert!(elapsed < Duration::from_millis(2_000), "{elapsed:?}");
        assert!(metrics.bytes_rx_ratelimited_total.get() > 0);
        assert_eq!(metrics.conns_rx_ratelimited_total.get(), 1);
    }

    #[tokio::test]
    async fn without_a_bucket_frames_pass_at_once() {
        let metrics = Arc::new(Metrics::default());
        let mut throttled = Throttled::new(frames(1_000, 1_000), None, metrics.clone());
        let start = Instant::now();
        let mut read = 0;
        while let Some(frame) = throttled.next().await {
            read += frame.unwrap().len();
        }
        assert_eq!(read, 1_000_000);
        assert!(start.elapsed() < Duration::from_millis(500));
        assert_eq!(metrics.bytes_rx_ratelimited_total.get(), 0);
    }
}
