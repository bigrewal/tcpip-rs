use std::{collections::HashMap, net::Ipv4Addr, time::Duration, time::Instant};

use crate::MacAddress;

use super::{ArpPacket, build_request, cache::ArpCache};

#[derive(Debug, PartialEq, Eq)]
pub enum ResolveOutcome {
    Resolved(MacAddress),
    SendRequest(ArpPacket<'static>),
    Pending,
    Failed,
}

#[derive(Clone, Copy, Debug)]
struct PendingResolution {
    attempts_sent: usize,
    next_retry_at: Instant,
}

#[derive(Debug)]
pub struct ArpResolver {
    local_mac: MacAddress,
    local_ip: Ipv4Addr,
    cache: ArpCache,
    pending: HashMap<Ipv4Addr, PendingResolution>,
    retry_interval: Duration,
    max_attempts: usize,
}

impl ArpResolver {
    pub fn new(
        local_mac: MacAddress,
        local_ip: Ipv4Addr,
        cache: ArpCache,
        retry_interval: Duration,
        max_attempts: usize,
    ) -> Self {
        Self {
            local_mac,
            local_ip,
            cache,
            pending: HashMap::new(),
            retry_interval,
            max_attempts,
        }
    }

    pub fn resolve(&mut self, next_hop_ip: Ipv4Addr, now: Instant) -> ResolveOutcome {
        if let Some(mac) = self.cache.lookup_mac(next_hop_ip, now) {
            self.pending.remove(&next_hop_ip);
            return ResolveOutcome::Resolved(mac);
        }

        if self.max_attempts == 0 {
            self.pending.remove(&next_hop_ip);
            return ResolveOutcome::Failed;
        }

        let Some(pending) = self.pending.get_mut(&next_hop_ip) else {
            self.pending.insert(
                next_hop_ip,
                PendingResolution {
                    attempts_sent: 1,
                    next_retry_at: next_retry_at(now, self.retry_interval),
                },
            );
            return ResolveOutcome::SendRequest(build_request(
                next_hop_ip,
                self.local_mac,
                self.local_ip,
            ));
        };

        if now < pending.next_retry_at {
            return ResolveOutcome::Pending;
        }

        if pending.attempts_sent >= self.max_attempts {
            self.pending.remove(&next_hop_ip);
            return ResolveOutcome::Failed;
        }

        pending.attempts_sent += 1;
        pending.next_retry_at = next_retry_at(now, self.retry_interval);
        ResolveOutcome::SendRequest(build_request(next_hop_ip, self.local_mac, self.local_ip))
    }

    pub fn observe(&mut self, packet: &ArpPacket<'_>, now: Instant) -> bool {
        if !self.cache.learn_from_packet(packet, now) {
            return false;
        }

        self.pending.remove(&packet.sender_ip);
        true
    }

    pub fn cached_mac(&mut self, ip: Ipv4Addr, now: Instant) -> Option<MacAddress> {
        self.cache.lookup_mac(ip, now)
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

fn next_retry_at(now: Instant, retry_interval: Duration) -> Instant {
    now.checked_add(retry_interval).unwrap_or(now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arp::{ArpOperation, HardwareType, ProtocolType};

    const LOCAL_MAC: MacAddress = MacAddress::new([0x02, 0, 0, 0, 0, 1]);
    const LOCAL_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);
    const TARGET_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
    const OTHER_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 2);
    const TARGET_MAC: MacAddress = MacAddress::new([0x02, 0, 0, 0, 0, 2]);
    const OTHER_MAC: MacAddress = MacAddress::new([0x02, 0, 0, 0, 0, 3]);
    const RETRY_INTERVAL: Duration = Duration::from_secs(1);
    const CACHE_TTL: Duration = Duration::from_secs(30);

    fn resolver(max_attempts: usize) -> ArpResolver {
        ArpResolver::new(
            LOCAL_MAC,
            LOCAL_IP,
            ArpCache::new(8, CACHE_TTL),
            RETRY_INTERVAL,
            max_attempts,
        )
    }

    fn incoming_packet(
        operation: ArpOperation,
        sender_ip: Ipv4Addr,
        sender_mac: MacAddress,
    ) -> ArpPacket<'static> {
        ArpPacket {
            hardware_type: HardwareType::Ethernet,
            protocol_type: ProtocolType::Ipv4,
            hardware_size: 6,
            protocol_size: 4,
            operation,
            sender_mac,
            sender_ip,
            target_mac: LOCAL_MAC,
            target_ip: LOCAL_IP,
            trailing_bytes: &[],
        }
    }

    fn request_from(outcome: ResolveOutcome) -> ArpPacket<'static> {
        match outcome {
            ResolveOutcome::SendRequest(request) => request,
            outcome => panic!("expected ARP request, got {outcome:?}"),
        }
    }

    #[test]
    fn cache_hit_is_resolved_without_sending_a_request() {
        let start = Instant::now();
        let mut cache = ArpCache::new(8, CACHE_TTL);
        cache.learn(TARGET_IP, TARGET_MAC, start);
        let mut resolver = ArpResolver::new(LOCAL_MAC, LOCAL_IP, cache, RETRY_INTERVAL, 3);

        assert_eq!(
            resolver.resolve(TARGET_IP, start),
            ResolveOutcome::Resolved(TARGET_MAC)
        );
        assert_eq!(resolver.pending_count(), 0);
    }

    #[test]
    fn first_cache_miss_sends_a_correct_request() {
        let start = Instant::now();
        let mut resolver = resolver(3);

        let request = request_from(resolver.resolve(TARGET_IP, start));

        assert_eq!(request.operation, ArpOperation::Request);
        assert_eq!(request.sender_mac, LOCAL_MAC);
        assert_eq!(request.sender_ip, LOCAL_IP);
        assert_eq!(request.target_mac, MacAddress::new([0; 6]));
        assert_eq!(request.target_ip, TARGET_IP);
        assert_eq!(resolver.pending_count(), 1);
    }

    #[test]
    fn repeated_calls_before_the_deadline_remain_pending() {
        let start = Instant::now();
        let mut resolver = resolver(3);
        request_from(resolver.resolve(TARGET_IP, start));

        assert_eq!(
            resolver.resolve(TARGET_IP, start + RETRY_INTERVAL - Duration::from_nanos(1)),
            ResolveOutcome::Pending
        );
    }

    #[test]
    fn retry_is_sent_exactly_at_the_deadline() {
        let start = Instant::now();
        let mut resolver = resolver(3);
        request_from(resolver.resolve(TARGET_IP, start));

        let retry = request_from(resolver.resolve(TARGET_IP, start + RETRY_INTERVAL));

        assert_eq!(retry.target_ip, TARGET_IP);
    }

    #[test]
    fn failure_occurs_one_interval_after_the_final_attempt() {
        let start = Instant::now();
        let mut resolver = resolver(3);

        assert!(matches!(
            resolver.resolve(TARGET_IP, start),
            ResolveOutcome::SendRequest(_)
        ));
        assert!(matches!(
            resolver.resolve(TARGET_IP, start + RETRY_INTERVAL),
            ResolveOutcome::SendRequest(_)
        ));
        assert!(matches!(
            resolver.resolve(TARGET_IP, start + RETRY_INTERVAL * 2),
            ResolveOutcome::SendRequest(_)
        ));
        assert_eq!(
            resolver.resolve(
                TARGET_IP,
                start + RETRY_INTERVAL * 3 - Duration::from_nanos(1)
            ),
            ResolveOutcome::Pending
        );
        assert_eq!(
            resolver.resolve(TARGET_IP, start + RETRY_INTERVAL * 3),
            ResolveOutcome::Failed
        );
        assert_eq!(resolver.pending_count(), 0);
    }

    #[test]
    fn incoming_reply_completes_a_pending_resolution() {
        let start = Instant::now();
        let mut resolver = resolver(3);
        request_from(resolver.resolve(TARGET_IP, start));
        let reply = incoming_packet(ArpOperation::Reply, TARGET_IP, TARGET_MAC);

        assert!(resolver.observe(&reply, start + Duration::from_millis(100)));
        assert_eq!(resolver.pending_count(), 0);
        assert_eq!(
            resolver.resolve(TARGET_IP, start + Duration::from_millis(100)),
            ResolveOutcome::Resolved(TARGET_MAC)
        );
    }

    #[test]
    fn incoming_request_can_also_complete_a_pending_resolution() {
        let start = Instant::now();
        let mut resolver = resolver(3);
        request_from(resolver.resolve(TARGET_IP, start));
        let request = incoming_packet(ArpOperation::Request, TARGET_IP, TARGET_MAC);

        assert!(resolver.observe(&request, start + Duration::from_millis(100)));
        assert_eq!(
            resolver.resolve(TARGET_IP, start + Duration::from_millis(100)),
            ResolveOutcome::Resolved(TARGET_MAC)
        );
    }

    #[test]
    fn unrelated_packet_does_not_complete_the_target_resolution() {
        let start = Instant::now();
        let mut resolver = resolver(3);
        request_from(resolver.resolve(TARGET_IP, start));
        let reply = incoming_packet(ArpOperation::Reply, OTHER_IP, OTHER_MAC);

        assert!(resolver.observe(&reply, start + Duration::from_millis(100)));
        assert_eq!(resolver.pending_count(), 1);
        assert_eq!(
            resolver.resolve(TARGET_IP, start + Duration::from_millis(100)),
            ResolveOutcome::Pending
        );
    }

    #[test]
    fn unknown_operation_is_ignored() {
        let start = Instant::now();
        let mut resolver = resolver(3);
        request_from(resolver.resolve(TARGET_IP, start));
        let packet = incoming_packet(ArpOperation::Unknown(99), TARGET_IP, TARGET_MAC);

        assert!(!resolver.observe(&packet, start + Duration::from_millis(100)));
        assert_eq!(resolver.pending_count(), 1);
        assert_eq!(
            resolver.resolve(TARGET_IP, start + Duration::from_millis(100)),
            ResolveOutcome::Pending
        );
    }

    #[test]
    fn expired_cached_mapping_starts_a_new_resolution() {
        let start = Instant::now();
        let mut cache = ArpCache::new(8, CACHE_TTL);
        cache.learn(TARGET_IP, TARGET_MAC, start);
        let mut resolver = ArpResolver::new(LOCAL_MAC, LOCAL_IP, cache, RETRY_INTERVAL, 3);

        assert!(matches!(
            resolver.resolve(TARGET_IP, start + CACHE_TTL),
            ResolveOutcome::SendRequest(_)
        ));
    }

    #[test]
    fn different_targets_have_independent_retry_state() {
        let start = Instant::now();
        let mut resolver = resolver(2);

        request_from(resolver.resolve(TARGET_IP, start));
        request_from(resolver.resolve(OTHER_IP, start + Duration::from_millis(500)));

        assert!(matches!(
            resolver.resolve(TARGET_IP, start + RETRY_INTERVAL),
            ResolveOutcome::SendRequest(_)
        ));
        assert_eq!(
            resolver.resolve(OTHER_IP, start + RETRY_INTERVAL),
            ResolveOutcome::Pending
        );
        assert_eq!(resolver.pending_count(), 2);
    }

    #[test]
    fn zero_max_attempts_fails_without_sending() {
        let start = Instant::now();
        let mut resolver = resolver(0);

        assert_eq!(resolver.resolve(TARGET_IP, start), ResolveOutcome::Failed);
        assert_eq!(resolver.pending_count(), 0);
    }
}
