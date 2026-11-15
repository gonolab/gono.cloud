//! The rate limits of protocol 15 that apply per device. They live in the hub, keyed by
//! device, so that reconnecting does not reset them.

use std::collections::VecDeque;

use gono_protocol::connect::limits;
use tokio::time::Instant;

/// Hellos per device per minute: a device that reconnects faster is closed with `4029`.
pub(crate) const HELLOS_PER_MINUTE: u32 = 20;

/// A token bucket: `rate` per second, at most `burst` at once.
#[derive(Debug)]
pub(crate) struct Bucket {
    tokens: f64,
    rate: f64,
    burst: f64,
    at: Instant,
}

impl Bucket {
    pub(crate) fn new(rate: u32, burst: u32) -> Self {
        Self {
            tokens: f64::from(burst),
            rate: f64::from(rate),
            burst: f64::from(burst),
            at: Instant::now(),
        }
    }

    pub(crate) fn take(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.at).as_secs_f64();
        self.at = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// At most `max` events per minute.
#[derive(Debug)]
pub(crate) struct PerMinute {
    max: usize,
    times: VecDeque<i64>,
}

impl PerMinute {
    pub(crate) fn new(max: u32) -> Self {
        Self {
            max: usize::try_from(max).unwrap_or(usize::MAX),
            times: VecDeque::new(),
        }
    }

    pub(crate) fn allow(&mut self, now: i64) -> bool {
        while self.times.front().is_some_and(|at| now - at >= 60) {
            self.times.pop_front();
        }
        if self.times.len() >= self.max {
            return false;
        }
        self.times.push_back(now);
        true
    }
}

/// What a limit counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Limit {
    /// Any request: 10 per second, bursts of 100.
    Request,
    /// `publish`: 1 per second.
    Publish,
    /// `connect`: 30 per minute.
    Connect,
    /// `lookup`: 120 per minute.
    Lookup,
    /// `session` reports: 60 per minute.
    Report,
    /// `hello`: [`HELLOS_PER_MINUTE`].
    Hello,
}

/// The limits of one device.
#[derive(Debug)]
pub(crate) struct DeviceLimits {
    requests: Bucket,
    publishes: Bucket,
    connects: PerMinute,
    lookups: PerMinute,
    reports: PerMinute,
    hellos: PerMinute,
}

impl Default for DeviceLimits {
    fn default() -> Self {
        Self {
            requests: Bucket::new(limits::REQUESTS_PER_SECOND, limits::REQUEST_BURST),
            publishes: Bucket::new(1, 1),
            connects: PerMinute::new(limits::CONNECTS_PER_MINUTE),
            lookups: PerMinute::new(limits::LOOKUPS_PER_MINUTE),
            reports: PerMinute::new(limits::SESSIONS_PER_MINUTE),
            hellos: PerMinute::new(HELLOS_PER_MINUTE),
        }
    }
}

impl DeviceLimits {
    /// Counts one `limit` at `now` (UNIX seconds); `false` when it is over.
    pub(crate) fn allow(&mut self, limit: Limit, now: i64) -> bool {
        match limit {
            Limit::Request => self.requests.take(),
            Limit::Publish => self.publishes.take(),
            Limit::Connect => self.connects.allow(now),
            Limit::Lookup => self.lookups.allow(now),
            Limit::Report => self.reports.allow(now),
            Limit::Hello => self.hellos.allow(now),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_minute_limits_slide() {
        let mut limit = PerMinute::new(2);
        assert!(limit.allow(0));
        assert!(limit.allow(10));
        assert!(!limit.allow(59));
        assert!(limit.allow(60));
    }

    #[tokio::test(start_paused = true)]
    async fn buckets_refill() {
        let mut bucket = Bucket::new(1, 1);
        assert!(bucket.take());
        assert!(!bucket.take());
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        assert!(bucket.take());
    }
}
