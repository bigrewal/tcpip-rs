// offset
//   0       2       4   5       6       8           14        18          24      28
//   |       |       |   |       |       |           |         |           |       |
//   v       v       v   v       v       v           v         v           v       v
// +-------+-------+---+---+-----------+-----------+---------+-----------+---------+
// | HTYPE | PTYPE |HLEN|PLEN| OPER    | sender MAC|sender IP| target MAC|target IP|
// +-------+-------+---+---+-----------+-----------+---------+-----------+---------+
//  2 bytes 2 bytes 1   1    2 bytes      6 bytes    4 bytes   6 bytes    4 bytes

pub mod cache;
pub mod resolver;

use std::{fmt, net::Ipv4Addr};

pub const ARP_HEADER_LEN: usize = 28;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArpOperation {
    Request,
    Reply,
    Unknown(u16),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HardwareType {
    Ethernet = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolType {
    Ipv4 = 0x0800,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArpParseError {
    PacketTooShort { actual: usize, minimum: usize },
    UnsupportedHardwareType(u16),
    UnsupportedProtocolType(u16),
    InvalidHardwareAddressLength(u8),
    InvalidProtocolAddressLength(u8),
}

impl fmt::Display for ArpParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PacketTooShort { actual, minimum } => write!(
                formatter,
                "ARP packet is {actual} bytes long; expected at least {minimum} bytes"
            ),
            Self::UnsupportedHardwareType(value) => {
                write!(formatter, "unsupported ARP hardware type {value}")
            }
            Self::UnsupportedProtocolType(value) => {
                write!(formatter, "unsupported ARP protocol type 0x{value:04x}")
            }
            Self::InvalidHardwareAddressLength(value) => {
                write!(formatter, "invalid ARP hardware-address length {value}")
            }
            Self::InvalidProtocolAddressLength(value) => {
                write!(formatter, "invalid ARP protocol-address length {value}")
            }
        }
    }
}

impl std::error::Error for ArpParseError {}

#[derive(Debug, PartialEq, Eq)]
pub struct ArpPacket<'a> {
    pub hardware_type: HardwareType,
    pub protocol_type: ProtocolType,
    pub hardware_size: u8,
    pub protocol_size: u8,
    pub operation: ArpOperation,
    pub sender_mac: crate::MacAddress,
    pub sender_ip: Ipv4Addr,
    pub target_mac: crate::MacAddress,
    pub target_ip: Ipv4Addr,
    pub trailing_bytes: &'a [u8],
}

impl<'a> ArpPacket<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, ArpParseError> {
        let Some((header, trailing_bytes)) = data.split_at_checked(ARP_HEADER_LEN) else {
            return Err(ArpParseError::PacketTooShort {
                actual: data.len(),
                minimum: ARP_HEADER_LEN,
            });
        };

        let [
            hardware_type_0,
            hardware_type_1,
            protocol_type_0,
            protocol_type_1,
            hardware_size,
            protocol_size,
            operation_0,
            operation_1,
            sender_mac_0,
            sender_mac_1,
            sender_mac_2,
            sender_mac_3,
            sender_mac_4,
            sender_mac_5,
            sender_ip_0,
            sender_ip_1,
            sender_ip_2,
            sender_ip_3,
            target_mac_0,
            target_mac_1,
            target_mac_2,
            target_mac_3,
            target_mac_4,
            target_mac_5,
            target_ip_0,
            target_ip_1,
            target_ip_2,
            target_ip_3,
        ] = header
        else {
            return Err(ArpParseError::PacketTooShort {
                actual: data.len(),
                minimum: ARP_HEADER_LEN,
            });
        };

        let hardware_type = u16::from_be_bytes([*hardware_type_0, *hardware_type_1]);
        let protocol_type = u16::from_be_bytes([*protocol_type_0, *protocol_type_1]);
        let operation = u16::from_be_bytes([*operation_0, *operation_1]);

        Ok(ArpPacket {
            hardware_type: match hardware_type {
                1 => HardwareType::Ethernet,
                value => return Err(ArpParseError::UnsupportedHardwareType(value)),
            },
            protocol_type: match protocol_type {
                0x0800 => ProtocolType::Ipv4,
                value => return Err(ArpParseError::UnsupportedProtocolType(value)),
            },
            hardware_size: match *hardware_size {
                6 => 6,
                value => return Err(ArpParseError::InvalidHardwareAddressLength(value)),
            },
            protocol_size: match *protocol_size {
                4 => 4,
                value => return Err(ArpParseError::InvalidProtocolAddressLength(value)),
            },
            operation: match operation {
                1 => ArpOperation::Request,
                2 => ArpOperation::Reply,
                value => ArpOperation::Unknown(value),
            },
            sender_mac: crate::MacAddress::new([
                *sender_mac_0,
                *sender_mac_1,
                *sender_mac_2,
                *sender_mac_3,
                *sender_mac_4,
                *sender_mac_5,
            ]),
            sender_ip: Ipv4Addr::new(*sender_ip_0, *sender_ip_1, *sender_ip_2, *sender_ip_3),
            target_mac: crate::MacAddress::new([
                *target_mac_0,
                *target_mac_1,
                *target_mac_2,
                *target_mac_3,
                *target_mac_4,
                *target_mac_5,
            ]),
            target_ip: Ipv4Addr::new(*target_ip_0, *target_ip_1, *target_ip_2, *target_ip_3),
            trailing_bytes,
        })
    }

    pub fn write_to(&self, output: &mut [u8]) -> Result<usize, crate::SerializeError> {
        if output.len() < ARP_HEADER_LEN {
            return Err(crate::SerializeError::BufferTooSmall {
                actual: output.len(),
                required: ARP_HEADER_LEN,
            });
        }

        let hardware_type = match self.hardware_type {
            HardwareType::Ethernet => 1_u16,
        };
        let protocol_type = match self.protocol_type {
            ProtocolType::Ipv4 => 0x0800_u16,
        };
        let operation = match self.operation {
            ArpOperation::Request => 1_u16,
            ArpOperation::Reply => 2_u16,
            ArpOperation::Unknown(value) => value,
        };

        output[0..2].copy_from_slice(&hardware_type.to_be_bytes());
        output[2..4].copy_from_slice(&protocol_type.to_be_bytes());
        output[4] = self.hardware_size;
        output[5] = self.protocol_size;
        output[6..8].copy_from_slice(&operation.to_be_bytes());
        output[8..14].copy_from_slice(&self.sender_mac.octets());
        output[14..18].copy_from_slice(&self.sender_ip.octets());
        output[18..24].copy_from_slice(&self.target_mac.octets());
        output[24..28].copy_from_slice(&self.target_ip.octets());

        Ok(ARP_HEADER_LEN)
    }
}

pub fn build_reply(
    request: &ArpPacket<'_>,
    local_mac: crate::MacAddress,
    local_ip: Ipv4Addr,
) -> Option<ArpPacket<'static>> {
    if request.operation != ArpOperation::Request || request.target_ip != local_ip {
        return None;
    }

    Some(ArpPacket {
        hardware_type: HardwareType::Ethernet,
        protocol_type: ProtocolType::Ipv4,
        hardware_size: 6,
        protocol_size: 4,
        operation: ArpOperation::Reply,
        sender_mac: local_mac,
        sender_ip: local_ip,
        target_mac: request.sender_mac,
        target_ip: request.sender_ip,
        trailing_bytes: &[],
    })
}

pub fn build_request(
    target_ip: Ipv4Addr,
    source_mac: crate::MacAddress,
    source_ip: Ipv4Addr,
) -> ArpPacket<'static> {
    ArpPacket {
        hardware_type: HardwareType::Ethernet,
        protocol_type: ProtocolType::Ipv4,
        hardware_size: 6,
        protocol_size: 4,
        operation: ArpOperation::Request,
        sender_mac: source_mac,
        sender_ip: source_ip,
        target_mac: crate::MacAddress::new([0; 6]),
        target_ip,
        trailing_bytes: &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCAL_MAC: crate::MacAddress =
        crate::MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    const LOCAL_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
    const TARGET_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);

    const ARP_REQUEST: [u8; ARP_HEADER_LEN] = [
        0x00, 0x01, // hardware type: Ethernet
        0x08, 0x00, // protocol type: IPv4
        0x06, // hardware address length
        0x04, // protocol address length
        0x00, 0x01, // operation: request
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // sender MAC
        192, 168, 1, 10, // sender IP
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // unknown target MAC
        192, 168, 1, 1, // target IP
    ];

    const ARP_REPLY: [u8; ARP_HEADER_LEN] = [
        0x00, 0x01, // hardware type: Ethernet
        0x08, 0x00, // protocol type: IPv4
        0x06, // hardware address length
        0x04, // protocol address length
        0x00, 0x02, // operation: reply
        0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // sender MAC
        192, 168, 1, 1, // sender IP
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // target MAC
        192, 168, 1, 10, // target IP
    ];

    const BUILT_ARP_REQUEST: [u8; ARP_HEADER_LEN] = [
        0x00, 0x01, // hardware type: Ethernet
        0x08, 0x00, // protocol type: IPv4
        0x06, // hardware address length
        0x04, // protocol address length
        0x00, 0x01, // operation: request
        0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // sender MAC
        192, 168, 1, 1, // sender IP
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // unknown target MAC
        192, 168, 1, 10, // target IP
    ];

    const ETHERNET_ARP_REQUEST: [u8; 14 + ARP_HEADER_LEN] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // broadcast Ethernet destination
        0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // local Ethernet source
        0x08, 0x06, // EtherType: ARP
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, // ARP header
        0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // ARP sender MAC
        192, 168, 1, 1, // ARP sender IP
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // unknown ARP target MAC
        192, 168, 1, 10, // ARP target IP
    ];

    #[test]
    fn parses_the_arp_request() {
        let parsed = ArpPacket::parse(&ARP_REQUEST).unwrap();

        assert_eq!(parsed.hardware_type, HardwareType::Ethernet);
        assert_eq!(parsed.protocol_type, ProtocolType::Ipv4);
        assert_eq!(parsed.hardware_size, 6);
        assert_eq!(parsed.protocol_size, 4);
        assert_eq!(parsed.operation, ArpOperation::Request);
        assert_eq!(
            parsed.sender_mac,
            crate::MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
        );
        assert_eq!(parsed.sender_ip, Ipv4Addr::new(192, 168, 1, 10));
        assert_eq!(parsed.target_mac, crate::MacAddress::new([0; 6]));
        assert_eq!(parsed.target_ip, Ipv4Addr::new(192, 168, 1, 1));
        assert!(parsed.trailing_bytes.is_empty());
    }

    #[test]
    fn rejects_every_length_shorter_than_an_arp_packet() {
        for length in 0..ARP_HEADER_LEN {
            let data = vec![0; length];

            assert_eq!(
                ArpPacket::parse(&data),
                Err(ArpParseError::PacketTooShort {
                    actual: length,
                    minimum: ARP_HEADER_LEN,
                })
            );
        }
    }

    #[test]
    fn rejects_an_unsupported_hardware_type() {
        let mut data = ARP_REQUEST;
        data[0..2].copy_from_slice(&2_u16.to_be_bytes());

        assert_eq!(
            ArpPacket::parse(&data),
            Err(ArpParseError::UnsupportedHardwareType(2))
        );
    }

    #[test]
    fn rejects_an_unsupported_protocol_type() {
        let mut data = ARP_REQUEST;
        data[2..4].copy_from_slice(&0x86dd_u16.to_be_bytes());

        assert_eq!(
            ArpPacket::parse(&data),
            Err(ArpParseError::UnsupportedProtocolType(0x86dd))
        );
    }

    #[test]
    fn rejects_an_invalid_hardware_address_length() {
        let mut data = ARP_REQUEST;
        data[4] = 5;

        assert_eq!(
            ArpPacket::parse(&data),
            Err(ArpParseError::InvalidHardwareAddressLength(5))
        );
    }

    #[test]
    fn rejects_an_invalid_protocol_address_length() {
        let mut data = ARP_REQUEST;
        data[5] = 16;

        assert_eq!(
            ArpPacket::parse(&data),
            Err(ArpParseError::InvalidProtocolAddressLength(16))
        );
    }

    #[test]
    fn preserves_an_unknown_operation() {
        let mut data = ARP_REQUEST;
        data[6..8].copy_from_slice(&3_u16.to_be_bytes());

        let parsed = ArpPacket::parse(&data).unwrap();

        assert_eq!(parsed.operation, ArpOperation::Unknown(3));
    }

    #[test]
    fn accepts_trailing_ethernet_padding() {
        let mut data = ARP_REQUEST.to_vec();
        data.extend_from_slice(&[0; 18]);

        let parsed = ArpPacket::parse(&data).unwrap();

        assert_eq!(parsed.trailing_bytes, &[0; 18]);
    }

    #[test]
    fn serializes_the_exact_arp_reply() {
        let request = ArpPacket::parse(&ARP_REQUEST).unwrap();
        let reply = build_reply(&request, LOCAL_MAC, LOCAL_IP).unwrap();
        let mut output = [0; ARP_HEADER_LEN];

        let written = reply.write_to(&mut output).unwrap();

        assert_eq!(written, ARP_HEADER_LEN);
        assert_eq!(output, ARP_REPLY);
    }

    #[test]
    fn serialized_reply_round_trips_through_the_parser() {
        let request = ArpPacket::parse(&ARP_REQUEST).unwrap();
        let reply = build_reply(&request, LOCAL_MAC, LOCAL_IP).unwrap();
        let mut output = [0; ARP_HEADER_LEN];
        reply.write_to(&mut output).unwrap();

        let reparsed = ArpPacket::parse(&output).unwrap();

        assert_eq!(reparsed.operation, ArpOperation::Reply);
        assert_eq!(reparsed.sender_mac, LOCAL_MAC);
        assert_eq!(reparsed.sender_ip, LOCAL_IP);
        assert_eq!(reparsed.target_mac, request.sender_mac);
        assert_eq!(reparsed.target_ip, request.sender_ip);
    }

    #[test]
    fn serializer_rejects_every_short_buffer_without_modifying_it() {
        let packet = ArpPacket::parse(&ARP_REQUEST).unwrap();

        for length in 0..ARP_HEADER_LEN {
            let mut output = vec![0xa5; length];
            let original = output.clone();

            assert_eq!(
                packet.write_to(&mut output),
                Err(crate::SerializeError::BufferTooSmall {
                    actual: length,
                    required: ARP_HEADER_LEN,
                })
            );
            assert_eq!(output, original);
        }
    }

    #[test]
    fn serializer_preserves_an_unknown_operation() {
        let mut input = ARP_REQUEST;
        input[6..8].copy_from_slice(&0x1234_u16.to_be_bytes());
        let packet = ArpPacket::parse(&input).unwrap();
        let mut output = [0; ARP_HEADER_LEN];

        packet.write_to(&mut output).unwrap();

        assert_eq!(output, input);
    }

    #[test]
    fn request_for_another_ip_does_not_produce_a_reply() {
        let mut input = ARP_REQUEST;
        input[24..28].copy_from_slice(&Ipv4Addr::new(192, 168, 1, 99).octets());
        let request = ArpPacket::parse(&input).unwrap();

        assert!(build_reply(&request, LOCAL_MAC, LOCAL_IP).is_none());
    }

    #[test]
    fn an_arp_reply_does_not_produce_another_reply() {
        let reply = ArpPacket::parse(&ARP_REPLY).unwrap();

        assert!(build_reply(&reply, LOCAL_MAC, LOCAL_IP).is_none());
    }

    #[test]
    fn serializes_the_exact_ethernet_arp_reply() {
        let request = ArpPacket::parse(&ARP_REQUEST).unwrap();
        let reply = build_reply(&request, LOCAL_MAC, LOCAL_IP).unwrap();
        let mut arp_bytes = [0; ARP_HEADER_LEN];
        reply.write_to(&mut arp_bytes).unwrap();
        let frame = crate::EthernetFrame {
            destination_mac: request.sender_mac,
            source_mac: LOCAL_MAC,
            ether_type: crate::EtherType::Arp,
            payload: &arp_bytes,
        };
        let mut output = [0; 14 + ARP_HEADER_LEN];

        let written = frame.write_to(&mut output).unwrap();

        let mut expected = [0; 14 + ARP_HEADER_LEN];
        expected[0..6].copy_from_slice(&request.sender_mac.octets());
        expected[6..12].copy_from_slice(&LOCAL_MAC.octets());
        expected[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
        expected[14..].copy_from_slice(&ARP_REPLY);
        assert_eq!(written, expected.len());
        assert_eq!(output, expected);
    }

    #[test]
    fn builds_an_arp_request_with_an_unknown_target_mac() {
        let request = build_request(TARGET_IP, LOCAL_MAC, LOCAL_IP);

        assert_eq!(request.hardware_type, HardwareType::Ethernet);
        assert_eq!(request.protocol_type, ProtocolType::Ipv4);
        assert_eq!(request.hardware_size, 6);
        assert_eq!(request.protocol_size, 4);
        assert_eq!(request.operation, ArpOperation::Request);
        assert_eq!(request.sender_mac, LOCAL_MAC);
        assert_eq!(request.sender_ip, LOCAL_IP);
        assert_eq!(request.target_mac, crate::MacAddress::new([0; 6]));
        assert_ne!(request.target_mac, crate::MacAddress::BROADCAST);
        assert_eq!(request.target_ip, TARGET_IP);
        assert!(request.trailing_bytes.is_empty());
    }

    #[test]
    fn serializes_the_exact_built_arp_request() {
        let request = build_request(TARGET_IP, LOCAL_MAC, LOCAL_IP);
        let mut output = [0; ARP_HEADER_LEN];

        let written = request.write_to(&mut output).unwrap();

        assert_eq!(written, ARP_HEADER_LEN);
        assert_eq!(output, BUILT_ARP_REQUEST);
    }

    #[test]
    fn built_request_round_trips_through_the_parser() {
        let request = build_request(TARGET_IP, LOCAL_MAC, LOCAL_IP);
        let mut output = [0; ARP_HEADER_LEN];
        request.write_to(&mut output).unwrap();

        let reparsed = ArpPacket::parse(&output).unwrap();

        assert_eq!(reparsed.operation, ArpOperation::Request);
        assert_eq!(reparsed.sender_mac, LOCAL_MAC);
        assert_eq!(reparsed.sender_ip, LOCAL_IP);
        assert_eq!(reparsed.target_mac, crate::MacAddress::new([0; 6]));
        assert_eq!(reparsed.target_ip, TARGET_IP);
    }

    #[test]
    fn wraps_the_built_request_in_an_exact_broadcast_ethernet_frame() {
        let request = build_request(TARGET_IP, LOCAL_MAC, LOCAL_IP);
        let mut arp_bytes = [0; ARP_HEADER_LEN];
        request.write_to(&mut arp_bytes).unwrap();
        let frame = crate::EthernetFrame {
            destination_mac: crate::MacAddress::BROADCAST,
            source_mac: LOCAL_MAC,
            ether_type: crate::EtherType::Arp,
            payload: &arp_bytes,
        };
        let mut output = [0; 14 + ARP_HEADER_LEN];

        let written = frame.write_to(&mut output).unwrap();

        assert_eq!(written, ETHERNET_ARP_REQUEST.len());
        assert_eq!(output, ETHERNET_ARP_REQUEST);
        assert_eq!(&output[0..6], &[0xff; 6]);
        assert_eq!(&output[14 + 18..14 + 24], &[0x00; 6]);
    }
}
