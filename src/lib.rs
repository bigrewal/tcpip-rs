pub mod arp;
pub mod checksum;
pub mod device;
pub mod icmp;
pub mod interface;
pub mod ipv4;
pub mod runtime;

use std::fmt;

pub const ETHERNET_HEADER_LEN: usize = 14;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MacAddress([u8; 6]);

impl MacAddress {
    pub const BROADCAST: Self = Self([0xff; 6]);

    pub const fn new(octets: [u8; 6]) -> Self {
        Self(octets)
    }

    pub const fn octets(self) -> [u8; 6] {
        self.0
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EtherType {
    Ipv4,
    Arp,
    Ipv6,
    Unknown(u16),
}

impl EtherType {
    pub const fn from_u16(value: u16) -> Self {
        match value {
            0x0800 => Self::Ipv4,
            0x0806 => Self::Arp,
            0x86dd => Self::Ipv6,
            value => Self::Unknown(value),
        }
    }

    pub const fn as_u16(self) -> u16 {
        match self {
            Self::Ipv4 => 0x0800,
            Self::Arp => 0x0806,
            Self::Ipv6 => 0x86dd,
            Self::Unknown(value) => value,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct EthernetFrame<'a> {
    pub destination_mac: MacAddress,
    pub source_mac: MacAddress,
    pub ether_type: EtherType,
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EthernetParseError {
    FrameTooShort { actual: usize, minimum: usize },
}

impl fmt::Display for EthernetParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooShort { actual, minimum } => write!(
                formatter,
                "Ethernet frame is {actual} bytes long; expected at least {minimum} bytes"
            ),
        }
    }
}

impl std::error::Error for EthernetParseError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SerialiseError {
    BufferTooSmall { actual: usize, required: usize },
}

impl fmt::Display for SerialiseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooSmall { actual, required } => write!(
                formatter,
                "output buffer is {actual} bytes long; {required} bytes are required"
            ),
        }
    }
}

impl std::error::Error for SerialiseError {}

pub fn parse_eth_frame(data: &[u8]) -> Result<EthernetFrame<'_>, EthernetParseError> {
    let Some((header, payload)) = data.split_at_checked(ETHERNET_HEADER_LEN) else {
        return Err(EthernetParseError::FrameTooShort {
            actual: data.len(),
            minimum: ETHERNET_HEADER_LEN,
        });
    };

    let [
        destination_0,
        destination_1,
        destination_2,
        destination_3,
        destination_4,
        destination_5,
        source_0,
        source_1,
        source_2,
        source_3,
        source_4,
        source_5,
        type_0,
        type_1,
    ] = header
    else {
        return Err(EthernetParseError::FrameTooShort {
            actual: data.len(),
            minimum: ETHERNET_HEADER_LEN,
        });
    };

    let destination_mac = MacAddress::new([
        *destination_0,
        *destination_1,
        *destination_2,
        *destination_3,
        *destination_4,
        *destination_5,
    ]);
    let source_mac = MacAddress::new([
        *source_0, *source_1, *source_2, *source_3, *source_4, *source_5,
    ]);
    let ether_type = EtherType::from_u16(u16::from_be_bytes([*type_0, *type_1]));

    Ok(EthernetFrame {
        destination_mac,
        source_mac,
        ether_type,
        payload,
    })
}

impl EthernetFrame<'_> {
    pub fn write_to(&self, output: &mut [u8]) -> Result<usize, SerialiseError> {
        let required = ETHERNET_HEADER_LEN + self.payload.len();

        if output.len() < required {
            return Err(SerialiseError::BufferTooSmall {
                actual: output.len(),
                required,
            });
        }

        output[0..6].copy_from_slice(&self.destination_mac.octets());
        output[6..12].copy_from_slice(&self.source_mac.octets());
        output[12..14].copy_from_slice(&self.ether_type.as_u16().to_be_bytes());
        output[ETHERNET_HEADER_LEN..required].copy_from_slice(self.payload);

        Ok(required)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARP_REQUEST: [u8; 42] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // destination MAC
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // source MAC
        0x08, 0x06, // EtherType: ARP
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, // payload
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc0, 0xa8, 0x01, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xc0, 0xa8, 0x01, 0x01,
    ];

    #[test]
    fn parses_an_arp_frame() {
        let frame = parse_eth_frame(&ARP_REQUEST).unwrap();

        assert_eq!(frame.destination_mac, MacAddress::BROADCAST);
        assert_eq!(
            frame.source_mac,
            MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
        );
        assert_eq!(frame.ether_type, EtherType::Arp);
        assert_eq!(frame.payload, &ARP_REQUEST[ETHERNET_HEADER_LEN..]);
    }

    #[test]
    fn rejects_every_length_shorter_than_the_header() {
        for length in 0..ETHERNET_HEADER_LEN {
            let data = vec![0; length];

            assert_eq!(
                parse_eth_frame(&data),
                Err(EthernetParseError::FrameTooShort {
                    actual: length,
                    minimum: ETHERNET_HEADER_LEN,
                })
            );
        }
    }

    #[test]
    fn accepts_a_header_without_a_payload() {
        let data = [0; ETHERNET_HEADER_LEN];
        let frame = parse_eth_frame(&data).unwrap();

        assert!(frame.payload.is_empty());
    }

    #[test]
    fn preserves_an_unknown_ether_type() {
        let mut data = [0; ETHERNET_HEADER_LEN];
        data[12..14].copy_from_slice(&0x88b5_u16.to_be_bytes());

        let frame = parse_eth_frame(&data).unwrap();

        assert_eq!(frame.ether_type, EtherType::Unknown(0x88b5));
        assert_eq!(frame.ether_type.as_u16(), 0x88b5);
    }

    #[test]
    fn formats_a_mac_address() {
        let address = MacAddress::new([0x02, 0x00, 0x00, 0xab, 0x0c, 0x01]);

        assert_eq!(address.to_string(), "02:00:00:ab:0c:01");
    }

    #[test]
    fn serialises_the_exact_ethernet_frame() {
        let frame = parse_eth_frame(&ARP_REQUEST).unwrap();
        let mut output = [0; ARP_REQUEST.len()];

        let written = frame.write_to(&mut output).unwrap();

        assert_eq!(written, ARP_REQUEST.len());
        assert_eq!(output, ARP_REQUEST);
    }

    #[test]
    fn serialiser_rejects_every_short_buffer_without_modifying_it() {
        let frame = parse_eth_frame(&ARP_REQUEST).unwrap();

        for length in 0..ARP_REQUEST.len() {
            let mut output = vec![0xa5; length];
            let original = output.clone();

            assert_eq!(
                frame.write_to(&mut output),
                Err(SerialiseError::BufferTooSmall {
                    actual: length,
                    required: ARP_REQUEST.len(),
                })
            );
            assert_eq!(output, original);
        }
    }

    #[test]
    fn serialises_an_unknown_ether_type_and_arbitrary_payload() {
        let payload = [0xde, 0xad, 0xbe, 0xef];
        let frame = EthernetFrame {
            destination_mac: MacAddress::BROADCAST,
            source_mac: MacAddress::new([0x02, 0, 0, 0, 0, 1]),
            ether_type: EtherType::Unknown(0x88b5),
            payload: &payload,
        };
        let mut output = [0; ETHERNET_HEADER_LEN + 4];

        frame.write_to(&mut output).unwrap();

        assert_eq!(&output[12..14], &0x88b5_u16.to_be_bytes());
        assert_eq!(&output[ETHERNET_HEADER_LEN..], &payload);
    }
}
