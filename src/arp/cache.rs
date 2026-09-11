// Incoming ARP
//     └── learn sender IP → sender MAC
//           └── optionally generate reply

// Outgoing IPv4
//     └── look up next-hop IP
//           ├── hit  → construct Ethernet frame
//           └── miss → eventually send ARP request

use std::{collections::HashMap, net::Ipv4Addr, time::Duration, time::Instant};

use crate::{
    MacAddress,
    arp::{ArpOperation, ArpPacket},
};

#[derive(Clone, Copy, Debug)]
struct CacheEntry {
    mac: MacAddress,
    learned_at: Instant,
}

#[derive(Debug)]
pub struct ArpCache {
    ip_to_mac: HashMap<Ipv4Addr, CacheEntry>,
    max_entries: usize,
    ttl: Duration,
}

impl ArpCache {
    pub fn new(max_entries: usize, ttl: Duration) -> Self {
        Self {
            ip_to_mac: HashMap::with_capacity(max_entries),
            max_entries,
            ttl,
        }
    }

    pub fn learn(&mut self, ip: Ipv4Addr, mac: MacAddress, now: Instant) -> bool {
        if self.max_entries == 0 {
            return false;
        }

        self.remove_expired(now);

        if let Some(entry) = self.ip_to_mac.get_mut(&ip) {
            entry.mac = mac;
            entry.learned_at = now;
            return true;
        }

        if self.ip_to_mac.len() >= self.max_entries {
            self.remove_oldest();
        }

        self.ip_to_mac.insert(
            ip,
            CacheEntry {
                mac,
                learned_at: now,
            },
        );

        true
    }

    pub fn learn_from_packet(&mut self, packet: &ArpPacket<'_>, now: Instant) -> bool {
        match packet.operation {
            ArpOperation::Request | ArpOperation::Reply => {
                self.learn(packet.sender_ip, packet.sender_mac, now)
            }
            ArpOperation::Unknown(_) => false,
        }
    }

    pub fn lookup_mac(&mut self, ip: Ipv4Addr, now: Instant) -> Option<MacAddress> {
        self.remove_expired(now);
        self.ip_to_mac.get(&ip).map(|entry| entry.mac)
    }

    pub fn remove_expired(&mut self, now: Instant) -> usize {
        let previous_len = self.ip_to_mac.len();
        let ttl = self.ttl;

        self.ip_to_mac
            .retain(|_, entry| now.saturating_duration_since(entry.learned_at) < ttl);

        previous_len - self.ip_to_mac.len()
    }

    pub fn len(&self) -> usize {
        self.ip_to_mac.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ip_to_mac.is_empty()
    }

    fn remove_oldest(&mut self) {
        let oldest_ip = self
            .ip_to_mac
            .iter()
            .min_by_key(|(ip, entry)| (entry.learned_at, **ip))
            .map(|(ip, _)| *ip);

        if let Some(ip) = oldest_ip {
            self.ip_to_mac.remove(&ip);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arp::{HardwareType, ProtocolType};

    const IP_1: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
    const IP_2: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 2);
    const IP_3: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 3);
    const MAC_1: MacAddress = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    const MAC_2: MacAddress = MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    const MAC_3: MacAddress = MacAddress::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);

    fn packet(operation: ArpOperation) -> ArpPacket<'static> {
        ArpPacket {
            hardware_type: HardwareType::Ethernet,
            protocol_type: ProtocolType::Ipv4,
            hardware_size: 6,
            protocol_size: 4,
            operation,
            sender_mac: MAC_1,
            sender_ip: IP_1,
            target_mac: MAC_2,
            target_ip: IP_2,
            trailing_bytes: &[],
        }
    }

    #[test]
    fn inserts_and_looks_up_a_mapping() {
        let start = Instant::now();
        let mut cache = ArpCache::new(2, Duration::from_secs(5));

        cache.learn(IP_1, MAC_1, start);

        assert_eq!(cache.lookup_mac(IP_1, start), Some(MAC_1));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn returns_none_for_an_unknown_ip() {
        let start = Instant::now();
        let mut cache = ArpCache::new(2, Duration::from_secs(5));

        assert_eq!(cache.lookup_mac(IP_1, start), None);
    }

    #[test]
    fn entry_is_valid_before_but_not_at_the_expiration_boundary() {
        let start = Instant::now();
        let ttl = Duration::from_secs(10);
        let mut cache = ArpCache::new(2, ttl);
        cache.learn(IP_1, MAC_1, start);

        assert_eq!(
            cache.lookup_mac(IP_1, start + ttl - Duration::from_nanos(1)),
            Some(MAC_1)
        );
        assert_eq!(cache.lookup_mac(IP_1, start + ttl), None);
    }

    #[test]
    fn updating_changes_the_mac_and_refreshes_expiration() {
        let start = Instant::now();
        let ttl = Duration::from_secs(10);
        let mut cache = ArpCache::new(2, ttl);
        cache.learn(IP_1, MAC_1, start);
        cache.learn(IP_1, MAC_2, start + Duration::from_secs(9));

        assert_eq!(cache.lookup_mac(IP_1, start + ttl), Some(MAC_2));
        assert_eq!(
            cache.lookup_mac(IP_1, start + Duration::from_secs(19)),
            None
        );
    }

    #[test]
    fn remove_expired_removes_only_expired_entries() {
        let start = Instant::now();
        let ttl = Duration::from_secs(10);
        let mut cache = ArpCache::new(3, ttl);
        cache.learn(IP_1, MAC_1, start);
        cache.learn(IP_2, MAC_2, start + Duration::from_secs(5));

        assert_eq!(cache.remove_expired(start + ttl), 1);
        assert_eq!(cache.lookup_mac(IP_1, start + ttl), None);
        assert_eq!(cache.lookup_mac(IP_2, start + ttl), Some(MAC_2));
    }

    #[test]
    fn capacity_two_cache_holds_two_entries() {
        let start = Instant::now();
        let mut cache = ArpCache::new(2, Duration::from_secs(30));
        cache.learn(IP_1, MAC_1, start);
        cache.learn(IP_2, MAC_2, start + Duration::from_secs(1));

        assert_eq!(cache.len(), 2);
        let now = start + Duration::from_secs(1);
        assert_eq!(cache.lookup_mac(IP_1, now), Some(MAC_1));
        assert_eq!(cache.lookup_mac(IP_2, now), Some(MAC_2));
    }

    #[test]
    fn inserting_when_full_evicts_the_oldest_entry() {
        let start = Instant::now();
        let mut cache = ArpCache::new(2, Duration::from_secs(30));
        cache.learn(IP_1, MAC_1, start);
        cache.learn(IP_2, MAC_2, start + Duration::from_secs(1));
        cache.learn(IP_3, MAC_3, start + Duration::from_secs(2));

        assert_eq!(cache.len(), 2);
        let now = start + Duration::from_secs(2);
        assert_eq!(cache.lookup_mac(IP_1, now), None);
        assert_eq!(cache.lookup_mac(IP_2, now), Some(MAC_2));
        assert_eq!(cache.lookup_mac(IP_3, now), Some(MAC_3));
    }

    #[test]
    fn updating_a_full_cache_does_not_evict_an_entry() {
        let start = Instant::now();
        let mut cache = ArpCache::new(2, Duration::from_secs(30));
        cache.learn(IP_1, MAC_1, start);
        cache.learn(IP_2, MAC_2, start + Duration::from_secs(1));
        cache.learn(IP_1, MAC_3, start + Duration::from_secs(2));

        assert_eq!(cache.len(), 2);
        let now = start + Duration::from_secs(2);
        assert_eq!(cache.lookup_mac(IP_1, now), Some(MAC_3));
        assert_eq!(cache.lookup_mac(IP_2, now), Some(MAC_2));
    }

    #[test]
    fn expired_entry_is_removed_before_a_valid_entry_is_evicted() {
        let start = Instant::now();
        let ttl = Duration::from_secs(10);
        let mut cache = ArpCache::new(2, ttl);
        cache.learn(IP_1, MAC_1, start);
        cache.learn(IP_2, MAC_2, start + Duration::from_secs(5));
        cache.learn(IP_3, MAC_3, start + ttl);

        assert_eq!(cache.len(), 2);
        assert_eq!(cache.lookup_mac(IP_1, start + ttl), None);
        assert_eq!(cache.lookup_mac(IP_2, start + ttl), Some(MAC_2));
        assert_eq!(cache.lookup_mac(IP_3, start + ttl), Some(MAC_3));
    }

    #[test]
    fn zero_capacity_cache_never_stores_an_entry() {
        let start = Instant::now();
        let mut cache = ArpCache::new(0, Duration::from_secs(10));

        cache.learn(IP_1, MAC_1, start);

        assert!(cache.is_empty());
        assert_eq!(cache.lookup_mac(IP_1, start), None);
    }

    #[test]
    fn learns_only_the_sender_from_a_request() {
        let start = Instant::now();
        let mut cache = ArpCache::new(2, Duration::from_secs(10));
        let request = packet(ArpOperation::Request);

        assert!(cache.learn_from_packet(&request, start));
        assert_eq!(cache.lookup_mac(IP_1, start), Some(MAC_1));
        assert_eq!(cache.lookup_mac(IP_2, start), None);
    }

    #[test]
    fn learns_the_sender_from_a_reply() {
        let start = Instant::now();
        let mut cache = ArpCache::new(2, Duration::from_secs(10));
        let reply = packet(ArpOperation::Reply);

        assert!(cache.learn_from_packet(&reply, start));
        assert_eq!(cache.lookup_mac(IP_1, start), Some(MAC_1));
    }

    #[test]
    fn ignores_an_unknown_arp_operation() {
        let start = Instant::now();
        let mut cache = ArpCache::new(2, Duration::from_secs(10));
        let packet = packet(ArpOperation::Unknown(99));

        assert!(!cache.learn_from_packet(&packet, start));
        assert!(cache.is_empty());
    }
}
