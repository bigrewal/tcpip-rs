use std::{
    fmt,
    net::Ipv4Addr,
    time::{Duration, Instant},
};

use crate::{
    ETHERNET_HEADER_LEN, EtherType, EthernetFrame, EthernetParseError, MacAddress, SerialiseError,
    arp::{
        ARP_HEADER_LEN, ArpPacket, ArpParseError, build_reply, cache::ArpCache,
        resolver::ArpResolver,
    },
    icmp::{IcmpParseError, build_echo_reply, parse_icmp_message},
    ipv4::{
        IPV4_MIN_HEADER_LEN, Ipv4Packet, Ipv4ParseError, Ipv4Protocol, Ipv4SerialiseError,
        parse_ipv4_packet,
    },
    parse_eth_frame,
    udp::{
        UDP_HEADER_LEN, UdpParseError, UdpSerialiseError, parse_udp_datagram,
        serialise_udp_datagram, validate_udp_checksum,
    },
};

pub const DEFAULT_IPV4_TTL: u8 = 64;
pub const DEFAULT_ARP_CACHE_CAPACITY: usize = 64;
pub const DEFAULT_ARP_CACHE_TTL: Duration = Duration::from_secs(60);
pub const DEFAULT_ARP_RETRY_INTERVAL: Duration = Duration::from_secs(1);
pub const DEFAULT_ARP_MAX_ATTEMPTS: usize = 3;
pub const UDP_ECHO_PORT: u16 = 9000;

#[derive(Debug)]
pub struct NetworkInterface {
    pub mac_address: MacAddress,
    pub ipv4_address: Ipv4Addr,
    pub next_ipv4_identification: u16,
    arp_resolver: ArpResolver,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterfaceError {
    Ethernet(EthernetParseError),
    Ipv4(Ipv4ParseError),
    Icmp(IcmpParseError),
    Serialise(SerialiseError),
    Ipv4Serialise(Ipv4SerialiseError),
    Arp(ArpParseError),
    Udp(UdpParseError),
    UdpSerialise(UdpSerialiseError),
}

impl fmt::Display for InterfaceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ethernet(error) => write!(formatter, "invalid Ethernet frame: {error}"),
            Self::Ipv4(error) => write!(formatter, "invalid IPv4 packet: {error}"),
            Self::Icmp(error) => write!(formatter, "invalid ICMP message: {error}"),
            Self::Serialise(error) => write!(formatter, "could not serialise frame: {error}"),
            Self::Ipv4Serialise(error) => {
                write!(formatter, "could not serialise IPv4 packet: {error}")
            }
            Self::Arp(error) => write!(formatter, "invalid ARP packet: {error}"),
            Self::Udp(error) => write!(formatter, "invalid UDP datagram: {error}"),
            Self::UdpSerialise(error) => {
                write!(formatter, "could not serialise UDP datagram: {error}")
            }
        }
    }
}

impl std::error::Error for InterfaceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Ethernet(error) => Some(error),
            Self::Ipv4(error) => Some(error),
            Self::Icmp(error) => Some(error),
            Self::Serialise(error) => Some(error),
            Self::Ipv4Serialise(error) => Some(error),
            Self::Arp(error) => Some(error),
            Self::Udp(error) => Some(error),
            Self::UdpSerialise(error) => Some(error),
        }
    }
}

impl From<EthernetParseError> for InterfaceError {
    fn from(error: EthernetParseError) -> Self {
        Self::Ethernet(error)
    }
}

impl From<Ipv4ParseError> for InterfaceError {
    fn from(error: Ipv4ParseError) -> Self {
        Self::Ipv4(error)
    }
}

impl From<IcmpParseError> for InterfaceError {
    fn from(error: IcmpParseError) -> Self {
        Self::Icmp(error)
    }
}

impl From<SerialiseError> for InterfaceError {
    fn from(error: SerialiseError) -> Self {
        Self::Serialise(error)
    }
}

impl From<Ipv4SerialiseError> for InterfaceError {
    fn from(error: Ipv4SerialiseError) -> Self {
        Self::Ipv4Serialise(error)
    }
}

impl From<ArpParseError> for InterfaceError {
    fn from(error: ArpParseError) -> Self {
        Self::Arp(error)
    }
}

impl From<UdpParseError> for InterfaceError {
    fn from(error: UdpParseError) -> Self {
        Self::Udp(error)
    }
}

impl From<UdpSerialiseError> for InterfaceError {
    fn from(error: UdpSerialiseError) -> Self {
        Self::UdpSerialise(error)
    }
}

impl NetworkInterface {
    pub fn new(mac_address: MacAddress, ipv4_address: Ipv4Addr) -> Self {
        Self::with_arp_config(
            mac_address,
            ipv4_address,
            DEFAULT_ARP_CACHE_CAPACITY,
            DEFAULT_ARP_CACHE_TTL,
            DEFAULT_ARP_RETRY_INTERVAL,
            DEFAULT_ARP_MAX_ATTEMPTS,
        )
    }

    pub fn with_arp_config(
        mac_address: MacAddress,
        ipv4_address: Ipv4Addr,
        cache_capacity: usize,
        cache_ttl: Duration,
        retry_interval: Duration,
        max_attempts: usize,
    ) -> Self {
        Self {
            mac_address,
            ipv4_address,
            next_ipv4_identification: 0,
            arp_resolver: ArpResolver::new(
                mac_address,
                ipv4_address,
                ArpCache::new(cache_capacity, cache_ttl),
                retry_interval,
                max_attempts,
            ),
        }
    }

    pub fn process_frame(&mut self, input: &[u8]) -> Result<Option<Vec<u8>>, InterfaceError> {
        self.process_frame_at(input, Instant::now())
    }

    pub fn process_frame_at(
        &mut self,
        input: &[u8],
        now: Instant,
    ) -> Result<Option<Vec<u8>>, InterfaceError> {
        let ethernet = parse_eth_frame(input)?;

        match ethernet.ether_type {
            EtherType::Ipv4 if ethernet.destination_mac == self.mac_address => {
                self.process_ipv4_frame(&ethernet)
            }
            EtherType::Arp
                if ethernet.destination_mac == self.mac_address
                    || ethernet.destination_mac == MacAddress::BROADCAST =>
            {
                self.process_arp_frame(&ethernet, now)
            }
            EtherType::Ipv4 | EtherType::Arp | EtherType::Ipv6 | EtherType::Unknown(_) => Ok(None),
        }
    }

    pub fn cached_mac(&mut self, ip: Ipv4Addr, now: Instant) -> Option<MacAddress> {
        self.arp_resolver.cached_mac(ip, now)
    }

    fn process_ipv4_frame(
        &mut self,
        ethernet: &EthernetFrame<'_>,
    ) -> Result<Option<Vec<u8>>, InterfaceError> {
        let ipv4 = parse_ipv4_packet(ethernet.payload)?;

        if ipv4.destination != self.ipv4_address {
            return Ok(None);
        }
        if ipv4.more_fragments || ipv4.fragment_offset != 0 {
            return Ok(None);
        }
        match ipv4.protocol {
            Ipv4Protocol::Icmp => self.process_icmp_packet(ethernet, &ipv4),
            Ipv4Protocol::Udp => self.process_udp_datagram(ethernet, &ipv4),
            Ipv4Protocol::Tcp | Ipv4Protocol::Unknown(_) => Ok(None),
        }
    }

    fn process_icmp_packet(
        &mut self,
        ethernet: &EthernetFrame<'_>,
        ipv4: &Ipv4Packet<'_>,
    ) -> Result<Option<Vec<u8>>, InterfaceError> {
        let icmp_request = parse_icmp_message(ipv4.payload)?;
        let Some(icmp_reply) = build_echo_reply(&icmp_request) else {
            return Ok(None);
        };

        let mut icmp_bytes = vec![0; ipv4.payload.len()];
        let icmp_length = icmp_reply.write_to(&mut icmp_bytes)?;
        debug_assert_eq!(icmp_length, icmp_bytes.len());

        self.build_ipv4_reply(ethernet, ipv4, Ipv4Protocol::Icmp, &icmp_bytes)
    }

    fn process_udp_datagram(
        &mut self,
        ethernet: &EthernetFrame<'_>,
        ipv4: &Ipv4Packet<'_>,
    ) -> Result<Option<Vec<u8>>, InterfaceError> {
        validate_udp_checksum(ipv4.source, ipv4.destination, ipv4.payload)?;
        let request = parse_udp_datagram(ipv4.payload)?;

        if request.destination_port != UDP_ECHO_PORT || request.source_port == 0 {
            return Ok(None);
        }

        let mut udp_bytes = vec![0; UDP_HEADER_LEN + request.payload.len()];
        let udp_length = serialise_udp_datagram(
            self.ipv4_address,
            ipv4.source,
            UDP_ECHO_PORT,
            request.source_port,
            request.payload,
            &mut udp_bytes,
        )?;
        debug_assert_eq!(udp_length, udp_bytes.len());

        self.build_ipv4_reply(ethernet, ipv4, Ipv4Protocol::Udp, &udp_bytes)
    }

    fn build_ipv4_reply(
        &mut self,
        ethernet: &EthernetFrame<'_>,
        request: &Ipv4Packet<'_>,
        protocol: Ipv4Protocol,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>, InterfaceError> {
        let identification = self.next_ipv4_identification;
        let ipv4_reply = Ipv4Packet {
            dscp: request.dscp,
            ecn: request.ecn,
            identification,
            ttl: DEFAULT_IPV4_TTL,
            protocol,
            dont_fragment: false,
            more_fragments: false,
            fragment_offset: 0,
            source: self.ipv4_address,
            destination: request.source,
            options: &[],
            payload,
            trailing_bytes: &[],
        };
        let mut ipv4_bytes = vec![0; IPV4_MIN_HEADER_LEN + payload.len()];
        let ipv4_length = ipv4_reply.write_to(&mut ipv4_bytes)?;
        debug_assert_eq!(ipv4_length, ipv4_bytes.len());

        let ethernet_reply = EthernetFrame {
            destination_mac: ethernet.source_mac,
            source_mac: self.mac_address,
            ether_type: EtherType::Ipv4,
            payload: &ipv4_bytes,
        };
        let mut output = vec![0; ETHERNET_HEADER_LEN + ipv4_length];
        let ethernet_length = ethernet_reply.write_to(&mut output)?;
        debug_assert_eq!(ethernet_length, output.len());

        self.next_ipv4_identification = identification.wrapping_add(1);

        Ok(Some(output))
    }

    fn process_arp_frame(
        &mut self,
        ethernet: &EthernetFrame<'_>,
        now: Instant,
    ) -> Result<Option<Vec<u8>>, InterfaceError> {
        let request = ArpPacket::parse(ethernet.payload)?;
        self.arp_resolver.observe(&request, now);

        let Some(reply) = build_reply(&request, self.mac_address, self.ipv4_address) else {
            return Ok(None);
        };

        let mut arp_bytes = vec![0; ARP_HEADER_LEN];
        let arp_length = reply.write_to(&mut arp_bytes)?;
        debug_assert_eq!(arp_length, arp_bytes.len());

        let ethernet_reply = EthernetFrame {
            destination_mac: reply.target_mac,
            source_mac: self.mac_address,
            ether_type: EtherType::Arp,
            payload: &arp_bytes,
        };
        let mut output = vec![0; ETHERNET_HEADER_LEN + arp_length];
        let ethernet_length = ethernet_reply.write_to(&mut output)?;
        debug_assert_eq!(ethernet_length, output.len());

        Ok(Some(output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arp::{ArpOperation, HardwareType, ProtocolType},
        icmp::{IcmpEchoMessage, IcmpMessage},
        ipv4::Ipv4Protocol,
        udp::{parse_udp_datagram, serialise_udp_datagram, validate_udp_checksum},
    };

    const LOCAL_MAC: MacAddress = MacAddress::new([0x02, 0, 0, 0, 0, 1]);
    const REMOTE_MAC: MacAddress = MacAddress::new([0x02, 0, 0, 0, 0, 2]);
    const OTHER_MAC: MacAddress = MacAddress::new([0x02, 0, 0, 0, 0, 3]);
    const LOCAL_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);
    const REMOTE_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 20);
    const OTHER_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 30);
    const ECHO_PAYLOAD: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];

    fn interface() -> NetworkInterface {
        NetworkInterface::new(LOCAL_MAC, LOCAL_IP)
    }

    fn echo_message(reply: bool) -> IcmpMessage<'static> {
        let message = IcmpEchoMessage {
            identifier: 0x1234,
            sequence_number: 7,
            payload: &ECHO_PAYLOAD,
        };
        if reply {
            IcmpMessage::EchoReply(message)
        } else {
            IcmpMessage::EchoRequest(message)
        }
    }

    fn serialise_icmp(message: &IcmpMessage<'_>) -> Vec<u8> {
        let length = match message {
            IcmpMessage::EchoRequest(message) | IcmpMessage::EchoReply(message) => {
                crate::icmp::ICMP_ECHO_HEADER_LEN + message.payload.len()
            }
            IcmpMessage::Unknown { body, .. } => crate::icmp::ICMP_HEADER_LEN + body.len(),
        };
        let mut bytes = vec![0; length];
        assert_eq!(message.write_to(&mut bytes).unwrap(), length);
        bytes
    }

    fn ipv4_frame(
        destination_mac: MacAddress,
        destination_ip: Ipv4Addr,
        protocol: Ipv4Protocol,
        payload: &[u8],
        more_fragments: bool,
        fragment_offset: u16,
    ) -> Vec<u8> {
        let packet = Ipv4Packet {
            dscp: 10,
            ecn: 2,
            identification: 0xabcd,
            ttl: 31,
            protocol,
            dont_fragment: false,
            more_fragments,
            fragment_offset,
            source: REMOTE_IP,
            destination: destination_ip,
            options: &[],
            payload,
            trailing_bytes: &[],
        };
        let mut ipv4_bytes = vec![0; IPV4_MIN_HEADER_LEN + payload.len()];
        packet.write_to(&mut ipv4_bytes).unwrap();

        let frame = EthernetFrame {
            destination_mac,
            source_mac: REMOTE_MAC,
            ether_type: EtherType::Ipv4,
            payload: &ipv4_bytes,
        };
        let mut ethernet_bytes = vec![0; ETHERNET_HEADER_LEN + ipv4_bytes.len()];
        frame.write_to(&mut ethernet_bytes).unwrap();
        ethernet_bytes
    }

    fn echo_frame(reply: bool) -> Vec<u8> {
        let icmp_bytes = serialise_icmp(&echo_message(reply));
        ipv4_frame(
            LOCAL_MAC,
            LOCAL_IP,
            Ipv4Protocol::Icmp,
            &icmp_bytes,
            false,
            0,
        )
    }

    fn udp_frame(source_port: u16, destination_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut udp_bytes = vec![0; UDP_HEADER_LEN + payload.len()];
        serialise_udp_datagram(
            REMOTE_IP,
            LOCAL_IP,
            source_port,
            destination_port,
            payload,
            &mut udp_bytes,
        )
        .unwrap();
        ipv4_frame(LOCAL_MAC, LOCAL_IP, Ipv4Protocol::Udp, &udp_bytes, false, 0)
    }

    fn arp_frame(
        destination_mac: MacAddress,
        operation: ArpOperation,
        target_ip: Ipv4Addr,
    ) -> Vec<u8> {
        let target_mac = match operation {
            ArpOperation::Request => MacAddress::new([0; 6]),
            ArpOperation::Reply | ArpOperation::Unknown(_) => LOCAL_MAC,
        };
        let packet = ArpPacket {
            hardware_type: HardwareType::Ethernet,
            protocol_type: ProtocolType::Ipv4,
            hardware_size: 6,
            protocol_size: 4,
            operation,
            sender_mac: REMOTE_MAC,
            sender_ip: REMOTE_IP,
            target_mac,
            target_ip,
            trailing_bytes: &[],
        };
        let mut arp_bytes = [0; ARP_HEADER_LEN];
        packet.write_to(&mut arp_bytes).unwrap();

        let frame = EthernetFrame {
            destination_mac,
            source_mac: REMOTE_MAC,
            ether_type: EtherType::Arp,
            payload: &arp_bytes,
        };
        let mut ethernet_bytes = vec![0; ETHERNET_HEADER_LEN + ARP_HEADER_LEN];
        frame.write_to(&mut ethernet_bytes).unwrap();
        ethernet_bytes
    }

    #[test]
    fn replies_to_an_ethernet_ipv4_icmp_echo_request() {
        let mut interface = interface();

        let output = interface
            .process_frame(&echo_frame(false))
            .unwrap()
            .unwrap();

        let ethernet = parse_eth_frame(&output).unwrap();
        assert_eq!(ethernet.destination_mac, REMOTE_MAC);
        assert_eq!(ethernet.source_mac, LOCAL_MAC);
        assert_eq!(ethernet.ether_type, EtherType::Ipv4);

        let ipv4 = parse_ipv4_packet(ethernet.payload).unwrap();
        assert_eq!(ipv4.source, LOCAL_IP);
        assert_eq!(ipv4.destination, REMOTE_IP);
        assert_eq!(ipv4.protocol, Ipv4Protocol::Icmp);
        assert_eq!(ipv4.ttl, DEFAULT_IPV4_TTL);
        assert_eq!(ipv4.identification, 0);
        assert_eq!(ipv4.dscp, 10);
        assert_eq!(ipv4.ecn, 2);
        assert!(!ipv4.dont_fragment);
        assert!(!ipv4.more_fragments);
        assert_eq!(ipv4.fragment_offset, 0);
        assert!(ipv4.options.is_empty());
        assert!(ipv4.trailing_bytes.is_empty());

        assert_eq!(
            parse_icmp_message(ipv4.payload).unwrap(),
            IcmpMessage::EchoReply(IcmpEchoMessage {
                identifier: 0x1234,
                sequence_number: 7,
                payload: &ECHO_PAYLOAD,
            })
        );
    }

    #[test]
    fn replies_to_a_udp_echo_request() {
        let input = udp_frame(49152, UDP_ECHO_PORT, b"hello UDP");

        let output = interface().process_frame(&input).unwrap().unwrap();

        let ethernet = parse_eth_frame(&output).unwrap();
        assert_eq!(ethernet.destination_mac, REMOTE_MAC);
        assert_eq!(ethernet.source_mac, LOCAL_MAC);
        assert_eq!(ethernet.ether_type, EtherType::Ipv4);

        let ipv4 = parse_ipv4_packet(ethernet.payload).unwrap();
        assert_eq!(ipv4.source, LOCAL_IP);
        assert_eq!(ipv4.destination, REMOTE_IP);
        assert_eq!(ipv4.protocol, Ipv4Protocol::Udp);
        assert_eq!(ipv4.ttl, DEFAULT_IPV4_TTL);
        assert_eq!(ipv4.identification, 0);
        assert_eq!(ipv4.dscp, 10);
        assert_eq!(ipv4.ecn, 2);
        assert!(ipv4.options.is_empty());
        assert!(ipv4.trailing_bytes.is_empty());

        assert_eq!(
            validate_udp_checksum(ipv4.source, ipv4.destination, ipv4.payload),
            Ok(())
        );
        let udp = parse_udp_datagram(ipv4.payload).unwrap();
        assert_eq!(udp.source_port, UDP_ECHO_PORT);
        assert_eq!(udp.destination_port, 49152);
        assert_eq!(udp.payload, b"hello UDP");
        assert_ne!(udp.checksum, 0);
    }

    #[test]
    fn replies_to_a_broadcast_arp_request_for_its_ipv4_address() {
        let now = Instant::now();
        let input = arp_frame(MacAddress::BROADCAST, ArpOperation::Request, LOCAL_IP);
        let mut interface = interface();

        let output = interface.process_frame_at(&input, now).unwrap().unwrap();

        let ethernet = parse_eth_frame(&output).unwrap();
        assert_eq!(ethernet.destination_mac, REMOTE_MAC);
        assert_eq!(ethernet.source_mac, LOCAL_MAC);
        assert_eq!(ethernet.ether_type, EtherType::Arp);

        let arp = ArpPacket::parse(ethernet.payload).unwrap();
        assert_eq!(arp.operation, ArpOperation::Reply);
        assert_eq!(arp.sender_mac, LOCAL_MAC);
        assert_eq!(arp.sender_ip, LOCAL_IP);
        assert_eq!(arp.target_mac, REMOTE_MAC);
        assert_eq!(arp.target_ip, REMOTE_IP);
        assert!(arp.trailing_bytes.is_empty());
        assert_eq!(interface.cached_mac(REMOTE_IP, now), Some(REMOTE_MAC));
    }

    #[test]
    fn learns_a_broadcast_arp_request_for_another_ipv4_address_without_replying() {
        let now = Instant::now();
        let input = arp_frame(MacAddress::BROADCAST, ArpOperation::Request, OTHER_IP);
        let mut interface = interface();

        assert_eq!(interface.process_frame_at(&input, now), Ok(None));
        assert_eq!(interface.cached_mac(REMOTE_IP, now), Some(REMOTE_MAC));
    }

    #[test]
    fn learns_an_arp_reply_addressed_to_its_mac_without_replying() {
        let now = Instant::now();
        let input = arp_frame(LOCAL_MAC, ArpOperation::Reply, LOCAL_IP);
        let mut interface = interface();

        assert_eq!(interface.process_frame_at(&input, now), Ok(None));
        assert_eq!(interface.cached_mac(REMOTE_IP, now), Some(REMOTE_MAC));
    }

    #[test]
    fn ignores_arp_frames_addressed_to_another_mac_without_learning_them() {
        let now = Instant::now();
        let input = arp_frame(OTHER_MAC, ArpOperation::Request, LOCAL_IP);
        let mut interface = interface();

        assert_eq!(interface.process_frame_at(&input, now), Ok(None));
        assert_eq!(interface.cached_mac(REMOTE_IP, now), None);
    }

    #[test]
    fn ignores_unknown_arp_operations_without_learning_them() {
        let now = Instant::now();
        let input = arp_frame(MacAddress::BROADCAST, ArpOperation::Unknown(99), LOCAL_IP);
        let mut interface = interface();

        assert_eq!(interface.process_frame_at(&input, now), Ok(None));
        assert_eq!(interface.cached_mac(REMOTE_IP, now), None);
    }

    #[test]
    fn reports_malformed_arp_packets() {
        let payload = [0; ARP_HEADER_LEN - 1];
        let frame = EthernetFrame {
            destination_mac: MacAddress::BROADCAST,
            source_mac: REMOTE_MAC,
            ether_type: EtherType::Arp,
            payload: &payload,
        };
        let mut input = vec![0; ETHERNET_HEADER_LEN + payload.len()];
        frame.write_to(&mut input).unwrap();

        assert_eq!(
            interface().process_frame_at(&input, Instant::now()),
            Err(InterfaceError::Arp(ArpParseError::PacketTooShort {
                actual: ARP_HEADER_LEN - 1,
                minimum: ARP_HEADER_LEN,
            }))
        );
    }

    #[test]
    fn increments_the_ipv4_identification_for_each_reply() {
        let mut interface = interface();
        let request = echo_frame(false);

        for expected in [0, 1, 2] {
            let output = interface.process_frame(&request).unwrap().unwrap();
            let ethernet = parse_eth_frame(&output).unwrap();
            let ipv4 = parse_ipv4_packet(ethernet.payload).unwrap();

            assert_eq!(ipv4.identification, expected);
        }
    }

    #[test]
    fn ignores_frames_not_addressed_to_its_mac_address() {
        let icmp_bytes = serialise_icmp(&echo_message(false));
        let input = ipv4_frame(
            OTHER_MAC,
            LOCAL_IP,
            Ipv4Protocol::Icmp,
            &icmp_bytes,
            false,
            0,
        );

        assert_eq!(interface().process_frame(&input), Ok(None));
    }

    #[test]
    fn ignores_non_ipv4_ethernet_frames() {
        let input = EthernetFrame {
            destination_mac: LOCAL_MAC,
            source_mac: REMOTE_MAC,
            ether_type: EtherType::Unknown(0x88b5),
            payload: &[0xde, 0xad],
        };
        let mut bytes = [0; ETHERNET_HEADER_LEN + 2];
        input.write_to(&mut bytes).unwrap();

        assert_eq!(interface().process_frame(&bytes), Ok(None));
    }

    #[test]
    fn ignores_ipv4_packets_addressed_to_another_host() {
        let icmp_bytes = serialise_icmp(&echo_message(false));
        let input = ipv4_frame(
            LOCAL_MAC,
            OTHER_IP,
            Ipv4Protocol::Icmp,
            &icmp_bytes,
            false,
            0,
        );

        assert_eq!(interface().process_frame(&input), Ok(None));
    }

    #[test]
    fn ignores_unsupported_ipv4_protocols() {
        let input = ipv4_frame(
            LOCAL_MAC,
            LOCAL_IP,
            Ipv4Protocol::Tcp,
            &[0xde, 0xad],
            false,
            0,
        );

        assert_eq!(interface().process_frame(&input), Ok(None));
    }

    #[test]
    fn ignores_udp_datagrams_for_an_unbound_port() {
        let input = udp_frame(49152, UDP_ECHO_PORT + 1, b"hello UDP");

        assert_eq!(interface().process_frame(&input), Ok(None));
    }

    #[test]
    fn ignores_udp_datagrams_without_a_reply_port() {
        let input = udp_frame(0, UDP_ECHO_PORT, b"hello UDP");

        assert_eq!(interface().process_frame(&input), Ok(None));
    }

    #[test]
    fn ignores_fragmented_ipv4_packets_until_reassembly_is_supported() {
        let icmp_bytes = serialise_icmp(&echo_message(false));

        for (more_fragments, fragment_offset) in [(true, 0), (false, 1)] {
            let input = ipv4_frame(
                LOCAL_MAC,
                LOCAL_IP,
                Ipv4Protocol::Icmp,
                &icmp_bytes,
                more_fragments,
                fragment_offset,
            );

            assert_eq!(interface().process_frame(&input), Ok(None));
        }
    }

    #[test]
    fn ignores_echo_replies_and_unknown_icmp_messages() {
        let echo_reply = serialise_icmp(&echo_message(true));
        let unknown = serialise_icmp(&IcmpMessage::Unknown {
            message_type: 3,
            code: 1,
            body: &[0; 4],
        });

        for icmp_bytes in [echo_reply, unknown] {
            let input = ipv4_frame(
                LOCAL_MAC,
                LOCAL_IP,
                Ipv4Protocol::Icmp,
                &icmp_bytes,
                false,
                0,
            );

            assert_eq!(interface().process_frame(&input), Ok(None));
        }
    }

    #[test]
    fn reports_malformed_ethernet_frames() {
        assert_eq!(
            interface().process_frame(&[0; ETHERNET_HEADER_LEN - 1]),
            Err(InterfaceError::Ethernet(
                EthernetParseError::FrameTooShort {
                    actual: ETHERNET_HEADER_LEN - 1,
                    minimum: ETHERNET_HEADER_LEN,
                }
            ))
        );
    }

    #[test]
    fn reports_malformed_ipv4_packets() {
        let frame = EthernetFrame {
            destination_mac: LOCAL_MAC,
            source_mac: REMOTE_MAC,
            ether_type: EtherType::Ipv4,
            payload: &[0; IPV4_MIN_HEADER_LEN - 1],
        };
        let mut input = vec![0; ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN - 1];
        frame.write_to(&mut input).unwrap();

        assert_eq!(
            interface().process_frame(&input),
            Err(InterfaceError::Ipv4(Ipv4ParseError::PacketTooShort {
                actual: IPV4_MIN_HEADER_LEN - 1,
                minimum: IPV4_MIN_HEADER_LEN,
            }))
        );
    }

    #[test]
    fn reports_malformed_icmp_messages() {
        let mut icmp_bytes = serialise_icmp(&echo_message(false));
        icmp_bytes[8] ^= 1;
        let input = ipv4_frame(
            LOCAL_MAC,
            LOCAL_IP,
            Ipv4Protocol::Icmp,
            &icmp_bytes,
            false,
            0,
        );

        assert_eq!(
            interface().process_frame(&input),
            Err(InterfaceError::Icmp(IcmpParseError::InvalidChecksum))
        );
    }

    #[test]
    fn reports_malformed_udp_datagrams() {
        let input = ipv4_frame(
            LOCAL_MAC,
            LOCAL_IP,
            Ipv4Protocol::Udp,
            &[0; UDP_HEADER_LEN - 1],
            false,
            0,
        );

        assert_eq!(
            interface().process_frame(&input),
            Err(InterfaceError::Udp(UdpParseError::DatagramTooShort {
                actual: UDP_HEADER_LEN - 1,
                minimum: UDP_HEADER_LEN,
            }))
        );
    }

    #[test]
    fn reports_a_udp_checksum_failure() {
        let mut udp_bytes = vec![0; UDP_HEADER_LEN + 4];
        serialise_udp_datagram(
            REMOTE_IP,
            LOCAL_IP,
            49152,
            UDP_ECHO_PORT,
            b"ping",
            &mut udp_bytes,
        )
        .unwrap();
        udp_bytes[UDP_HEADER_LEN] ^= 1;
        let input = ipv4_frame(LOCAL_MAC, LOCAL_IP, Ipv4Protocol::Udp, &udp_bytes, false, 0);

        assert_eq!(
            interface().process_frame(&input),
            Err(InterfaceError::Udp(UdpParseError::InvalidChecksum))
        );
    }

    #[test]
    fn ignores_ipv4_trailing_padding_when_building_the_reply() {
        let mut input = echo_frame(false);
        input.extend_from_slice(&[0; 18]);

        let output = interface().process_frame(&input).unwrap().unwrap();

        assert_eq!(output.len(), ETHERNET_HEADER_LEN + IPV4_MIN_HEADER_LEN + 12);
        let ethernet = parse_eth_frame(&output).unwrap();
        let ipv4 = parse_ipv4_packet(ethernet.payload).unwrap();
        let IcmpMessage::EchoReply(message) = parse_icmp_message(ipv4.payload).unwrap() else {
            panic!("expected an Echo Reply");
        };
        assert_eq!(message.payload, ECHO_PAYLOAD);
    }
}
