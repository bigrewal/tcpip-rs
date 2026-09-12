// Ipv4 Parser
// | Offset | Field |
// |---:|---|
// | 0 | Version and IHL |
// | 1 | DSCP and ECN |
// | 2–3 | Total length |
// | 4–5 | Identification |
// | 6–7 | Flags and fragment offset |
// | 8 | TTL |
// | 9 | Protocol |
// | 10–11 | Header checksum |
// | 12–15 | Source address |
// | 16–19 | Destination address |
// | 20+ | Options, when IHL exceeds 5 |

use std::{fmt, net::Ipv4Addr};

use crate::checksum::checksum;

pub const IPV4_MIN_HEADER_LEN: usize = 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipv4ParseError {
    PacketTooShort {
        actual: usize,
        minimum: usize,
    },
    InvalidVersion(u8),
    InvalidIhl(u8),
    TruncatedHeader {
        actual: usize,
        required: usize,
    },
    TotalLengthTooSmall {
        total_length: usize,
        header_length: usize,
    },
    TruncatedPacket {
        actual: usize,
        declared: usize,
    },
    InvalidChecksum,
    ReservedFlagSet,
}

impl fmt::Display for Ipv4ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PacketTooShort { actual, minimum } => write!(
                formatter,
                "IPv4 packet is {actual} bytes long; expected at least {minimum} bytes"
            ),
            Self::InvalidVersion(version) => {
                write!(formatter, "invalid IP version {version}; expected IPv4")
            }
            Self::InvalidIhl(ihl) => write!(formatter, "invalid IPv4 IHL {ihl}; minimum is 5"),
            Self::TruncatedHeader { actual, required } => write!(
                formatter,
                "IPv4 header requires {required} bytes but only {actual} are available"
            ),
            Self::TotalLengthTooSmall {
                total_length,
                header_length,
            } => write!(
                formatter,
                "IPv4 total length {total_length} is smaller than header length {header_length}"
            ),
            Self::TruncatedPacket { actual, declared } => write!(
                formatter,
                "IPv4 packet declares {declared} bytes but only {actual} are available"
            ),
            Self::InvalidChecksum => write!(formatter, "invalid IPv4 header checksum"),
            Self::ReservedFlagSet => write!(formatter, "reserved IPv4 fragmentation flag is set"),
        }
    }
}

impl std::error::Error for Ipv4ParseError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipv4Protocol {
    Icmp,
    Tcp,
    Udp,
    Unknown(u8),
}

impl From<u8> for Ipv4Protocol {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Icmp,
            6 => Self::Tcp,
            17 => Self::Udp,
            value => Self::Unknown(value),
        }
    }
}

impl Ipv4Protocol {
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Icmp => 1,
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Unknown(value) => value,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Ipv4Packet<'a> {
    pub dscp: u8,
    pub ecn: u8,
    pub identification: u16,
    pub ttl: u8,
    pub protocol: Ipv4Protocol,
    pub dont_fragment: bool,
    pub more_fragments: bool,
    /// The wire value, measured in units of eight bytes.
    pub fragment_offset: u16,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub options: &'a [u8],
    pub payload: &'a [u8],
    pub trailing_bytes: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipv4SerialiseError {
    BufferTooSmall { actual: usize, required: usize },
    TotalLengthTooLarge { actual: usize, maximum: usize },
    OptionsNotMultipleOfFour { actual: usize },
    OptionsTooLong { actual: usize, maximum: usize },
    FragmentOffsetOutOfRange { value: u16 },
    DscpOutOfRange { value: u8 },
    EcnOutOfRange { value: u8 },
}

impl fmt::Display for Ipv4SerialiseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooSmall { actual, required } => write!(
                formatter,
                "output buffer is {actual} bytes long; {required} bytes are required"
            ),
            Self::TotalLengthTooLarge { actual, maximum } => write!(
                formatter,
                "IPv4 total length is {actual} bytes; maximum is {maximum}"
            ),
            Self::OptionsNotMultipleOfFour { actual } => write!(
                formatter,
                "IPv4 options are {actual} bytes long; must be a multiple of four"
            ),
            Self::OptionsTooLong { actual, maximum } => write!(
                formatter,
                "IPv4 options are {actual} bytes long; maximum is {maximum}"
            ),
            Self::FragmentOffsetOutOfRange { value } => write!(
                formatter,
                "IPv4 fragment offset {value} is out of range (0–8191)"
            ),
            Self::DscpOutOfRange { value } => {
                write!(formatter, "IPv4 DSCP value {value} is out of range (0–63)")
            }
            Self::EcnOutOfRange { value } => {
                write!(formatter, "IPv4 ECN value {value} is out of range (0–3)")
            }
        }
    }
}

impl std::error::Error for Ipv4SerialiseError {}

impl Ipv4Packet<'_> {
    pub const fn fragment_offset_bytes(&self) -> usize {
        self.fragment_offset as usize * 8
    }

    pub fn write_to(&self, output: &mut [u8]) -> Result<usize, Ipv4SerialiseError> {
        if self.options.len() > 40 {
            return Err(Ipv4SerialiseError::OptionsTooLong {
                actual: self.options.len(),
                maximum: 40,
            });
        }
        if self.options.len() % 4 != 0 {
            return Err(Ipv4SerialiseError::OptionsNotMultipleOfFour {
                actual: self.options.len(),
            });
        }

        if self.dscp > 63 {
            return Err(Ipv4SerialiseError::DscpOutOfRange { value: self.dscp });
        }
        if self.ecn > 3 {
            return Err(Ipv4SerialiseError::EcnOutOfRange { value: self.ecn });
        }
        if self.fragment_offset > 0x1fff {
            return Err(Ipv4SerialiseError::FragmentOffsetOutOfRange {
                value: self.fragment_offset,
            });
        }

        let header_length = IPV4_MIN_HEADER_LEN + self.options.len();
        let maximum_total_length = usize::from(u16::MAX);
        if self.payload.len() > maximum_total_length - header_length {
            return Err(Ipv4SerialiseError::TotalLengthTooLarge {
                actual: header_length.saturating_add(self.payload.len()),
                maximum: maximum_total_length,
            });
        }
        let total_length = header_length + self.payload.len();

        if output.len() < total_length {
            return Err(Ipv4SerialiseError::BufferTooSmall {
                actual: output.len(),
                required: total_length,
            });
        }

        output[0] = (4 << 4) | (header_length / 4) as u8;
        output[1] = (self.dscp << 2) | self.ecn;
        output[2..4].copy_from_slice(&(total_length as u16).to_be_bytes());
        output[4..6].copy_from_slice(&self.identification.to_be_bytes());
        let flags_and_fragment_offset = ((self.dont_fragment as u16) << 14)
            | ((self.more_fragments as u16) << 13)
            | (self.fragment_offset & 0x1fff);

        output[6..8].copy_from_slice(&flags_and_fragment_offset.to_be_bytes());
        output[8] = self.ttl;
        output[9] = self.protocol.as_u8();
        output[10..12].fill(0);
        output[12..16].copy_from_slice(&self.source.octets());
        output[16..20].copy_from_slice(&self.destination.octets());
        output[20..header_length].copy_from_slice(self.options);

        let checksum_value = checksum(&output[..header_length]);
        output[10..12].copy_from_slice(&checksum_value.to_be_bytes());

        output[header_length..total_length].copy_from_slice(self.payload);

        Ok(total_length)
    }
}

pub fn parse_ipv4_packet(data: &[u8]) -> Result<Ipv4Packet<'_>, Ipv4ParseError> {
    if data.len() < IPV4_MIN_HEADER_LEN {
        return Err(Ipv4ParseError::PacketTooShort {
            actual: data.len(),
            minimum: IPV4_MIN_HEADER_LEN,
        });
    }

    let version = data[0] >> 4;
    if version != 4 {
        return Err(Ipv4ParseError::InvalidVersion(version));
    }

    let ihl = data[0] & 0x0f;
    if ihl < 5 {
        return Err(Ipv4ParseError::InvalidIhl(ihl));
    }

    let header_length = usize::from(ihl) * 4;
    if data.len() < header_length {
        return Err(Ipv4ParseError::TruncatedHeader {
            actual: data.len(),
            required: header_length,
        });
    }

    let total_length = usize::from(u16::from_be_bytes([data[2], data[3]]));
    if total_length < header_length {
        return Err(Ipv4ParseError::TotalLengthTooSmall {
            total_length,
            header_length,
        });
    }
    if data.len() < total_length {
        return Err(Ipv4ParseError::TruncatedPacket {
            actual: data.len(),
            declared: total_length,
        });
    }

    let flags_and_fragment_offset = u16::from_be_bytes([data[6], data[7]]);
    if flags_and_fragment_offset & 0x8000 != 0 {
        return Err(Ipv4ParseError::ReservedFlagSet);
    }

    let header = &data[..header_length];
    if checksum(header) != 0 {
        return Err(Ipv4ParseError::InvalidChecksum);
    }

    Ok(Ipv4Packet {
        dscp: data[1] >> 2,
        ecn: data[1] & 0x03,
        identification: u16::from_be_bytes([data[4], data[5]]),
        ttl: data[8],
        protocol: Ipv4Protocol::from(data[9]),
        dont_fragment: flags_and_fragment_offset & 0x4000 != 0,
        more_fragments: flags_and_fragment_offset & 0x2000 != 0,
        fragment_offset: flags_and_fragment_offset & 0x1fff,
        source: Ipv4Addr::new(data[12], data[13], data[14], data[15]),
        destination: Ipv4Addr::new(data[16], data[17], data[18], data[19]),
        options: &data[IPV4_MIN_HEADER_LEN..header_length],
        payload: &data[header_length..total_length],
        trailing_bytes: &data[total_length..],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimum_packet() -> Vec<u8> {
        let mut packet = vec![
            0x45, // version 4, IHL 5
            0xab, // DSCP 42, ECN 3
            0x00, 0x14, // total length 20
            0x12, 0x34, // identification
            0x40, 0x00, // don't fragment, offset zero
            64,   // TTL
            17,   // UDP
            0x00, 0x00, // checksum, filled below
            192, 168, 1, 10, // source
            192, 168, 1, 1, // destination
        ];
        update_checksum(&mut packet);
        packet
    }

    fn update_checksum(packet: &mut [u8]) {
        let header_length = usize::from(packet[0] & 0x0f) * 4;
        packet[10] = 0;
        packet[11] = 0;
        let value = checksum(&packet[..header_length]);
        packet[10..12].copy_from_slice(&value.to_be_bytes());
    }

    fn serialisable_packet() -> Ipv4Packet<'static> {
        Ipv4Packet {
            dscp: 42,
            ecn: 3,
            identification: 0x1234,
            ttl: 64,
            protocol: Ipv4Protocol::Udp,
            dont_fragment: true,
            more_fragments: false,
            fragment_offset: 0,
            source: Ipv4Addr::new(192, 168, 1, 10),
            destination: Ipv4Addr::new(192, 168, 1, 1),
            options: &[],
            payload: &[],
            trailing_bytes: &[],
        }
    }

    #[test]
    fn parses_a_valid_minimum_header() {
        let packet = minimum_packet();

        let parsed = parse_ipv4_packet(&packet).unwrap();

        assert_eq!(parsed.dscp, 42);
        assert_eq!(parsed.ecn, 3);
        assert_eq!(parsed.identification, 0x1234);
        assert_eq!(parsed.ttl, 64);
        assert_eq!(parsed.protocol, Ipv4Protocol::Udp);
        assert!(parsed.dont_fragment);
        assert!(!parsed.more_fragments);
        assert_eq!(parsed.fragment_offset, 0);
        assert_eq!(parsed.source, Ipv4Addr::new(192, 168, 1, 10));
        assert_eq!(parsed.destination, Ipv4Addr::new(192, 168, 1, 1));
        assert!(parsed.options.is_empty());
        assert!(parsed.payload.is_empty());
        assert!(parsed.trailing_bytes.is_empty());
    }

    #[test]
    fn rejects_every_input_shorter_than_the_minimum_header() {
        for length in 0..IPV4_MIN_HEADER_LEN {
            let data = vec![0; length];

            assert_eq!(
                parse_ipv4_packet(&data),
                Err(Ipv4ParseError::PacketTooShort {
                    actual: length,
                    minimum: IPV4_MIN_HEADER_LEN,
                })
            );
        }
    }

    #[test]
    fn rejects_a_non_ipv4_version() {
        let mut packet = minimum_packet();
        packet[0] = 0x65;

        assert_eq!(
            parse_ipv4_packet(&packet),
            Err(Ipv4ParseError::InvalidVersion(6))
        );
    }

    #[test]
    fn rejects_an_ihl_smaller_than_five() {
        let mut packet = minimum_packet();
        packet[0] = 0x44;

        assert_eq!(
            parse_ipv4_packet(&packet),
            Err(Ipv4ParseError::InvalidIhl(4))
        );
    }

    #[test]
    fn rejects_a_truncated_options_area_without_panicking() {
        let mut packet = minimum_packet();
        packet[0] = 0x46;

        assert_eq!(
            parse_ipv4_packet(&packet),
            Err(Ipv4ParseError::TruncatedHeader {
                actual: IPV4_MIN_HEADER_LEN,
                required: 24,
            })
        );
    }

    #[test]
    fn rejects_total_length_smaller_than_the_header() {
        let mut packet = minimum_packet();
        packet.extend_from_slice(&[0; 4]);
        packet[0] = 0x46;

        assert_eq!(
            parse_ipv4_packet(&packet),
            Err(Ipv4ParseError::TotalLengthTooSmall {
                total_length: 20,
                header_length: 24,
            })
        );
    }

    #[test]
    fn rejects_a_packet_shorter_than_its_declared_total_length() {
        let mut packet = minimum_packet();
        packet[2..4].copy_from_slice(&24_u16.to_be_bytes());
        update_checksum(&mut packet);

        assert_eq!(
            parse_ipv4_packet(&packet),
            Err(Ipv4ParseError::TruncatedPacket {
                actual: IPV4_MIN_HEADER_LEN,
                declared: 24,
            })
        );
    }

    #[test]
    fn rejects_an_invalid_header_checksum() {
        let mut packet = minimum_packet();
        packet[4] ^= 1;

        assert_eq!(
            parse_ipv4_packet(&packet),
            Err(Ipv4ParseError::InvalidChecksum)
        );
    }

    #[test]
    fn recognizes_known_protocols_and_preserves_unknown_values() {
        for (wire_value, expected) in [
            (1, Ipv4Protocol::Icmp),
            (6, Ipv4Protocol::Tcp),
            (17, Ipv4Protocol::Udp),
            (253, Ipv4Protocol::Unknown(253)),
        ] {
            let mut packet = minimum_packet();
            packet[9] = wire_value;
            update_checksum(&mut packet);

            assert_eq!(parse_ipv4_packet(&packet).unwrap().protocol, expected);
        }
    }

    #[test]
    fn parses_fragmentation_flags_and_eight_byte_offset_units() {
        let mut packet = minimum_packet();
        packet[6..8].copy_from_slice(&0x2005_u16.to_be_bytes());
        update_checksum(&mut packet);

        let parsed = parse_ipv4_packet(&packet).unwrap();

        assert!(!parsed.dont_fragment);
        assert!(parsed.more_fragments);
        assert_eq!(parsed.fragment_offset, 5);
        assert_eq!(parsed.fragment_offset_bytes(), 40);
    }

    #[test]
    fn rejects_the_reserved_fragmentation_flag() {
        let mut packet = minimum_packet();
        packet[6..8].copy_from_slice(&0x8000_u16.to_be_bytes());
        update_checksum(&mut packet);

        assert_eq!(
            parse_ipv4_packet(&packet),
            Err(Ipv4ParseError::ReservedFlagSet)
        );
    }

    #[test]
    fn borrows_ipv4_options() {
        let mut packet = minimum_packet();
        packet.extend_from_slice(&[0x01, 0x01, 0x00, 0x00]);
        packet[0] = 0x46;
        packet[2..4].copy_from_slice(&24_u16.to_be_bytes());
        update_checksum(&mut packet);

        let parsed = parse_ipv4_packet(&packet).unwrap();

        assert_eq!(parsed.options, &[0x01, 0x01, 0x00, 0x00]);
        assert_eq!(parsed.options.as_ptr(), packet[20..24].as_ptr());
    }

    #[test]
    fn separates_payload_from_trailing_ethernet_padding() {
        let mut packet = minimum_packet();
        packet.extend_from_slice(&[0xde, 0xad, 0xbe]);
        packet.extend_from_slice(&[0; 7]);
        packet[2..4].copy_from_slice(&23_u16.to_be_bytes());
        update_checksum(&mut packet);

        let parsed = parse_ipv4_packet(&packet).unwrap();

        assert_eq!(parsed.payload, &[0xde, 0xad, 0xbe]);
        assert_eq!(parsed.trailing_bytes, &[0; 7]);
    }

    #[test]
    fn accepts_ttl_zero_as_structurally_valid() {
        let mut packet = minimum_packet();
        packet[8] = 0;
        update_checksum(&mut packet);

        assert_eq!(parse_ipv4_packet(&packet).unwrap().ttl, 0);
    }

    #[test]
    fn detects_corruption_in_each_nonstructural_header_field() {
        for offset in [1, 4, 5, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19] {
            let mut packet = minimum_packet();
            packet[offset] ^= 1;

            assert_eq!(
                parse_ipv4_packet(&packet),
                Err(Ipv4ParseError::InvalidChecksum),
                "corruption at header byte {offset} was not detected"
            );
        }
    }

    #[test]
    fn detects_corruption_in_an_option_byte() {
        let mut packet = minimum_packet();
        packet.extend_from_slice(&[0x01, 0x01, 0x00, 0x00]);
        packet[0] = 0x46;
        packet[2..4].copy_from_slice(&24_u16.to_be_bytes());
        update_checksum(&mut packet);
        packet[20] ^= 1;

        assert_eq!(
            parse_ipv4_packet(&packet),
            Err(Ipv4ParseError::InvalidChecksum)
        );
    }

    #[test]
    fn serialises_the_exact_minimum_ipv4_packet() {
        let packet = serialisable_packet();
        let mut output = [0; IPV4_MIN_HEADER_LEN];

        let written = packet.write_to(&mut output).unwrap();

        let expected = [
            0x45, 0xab, 0x00, 0x14, 0x12, 0x34, 0x40, 0x00, 64, 17, 0xa4, 0x9e, 192, 168, 1, 10,
            192, 168, 1, 1,
        ];
        assert_eq!(written, IPV4_MIN_HEADER_LEN);
        assert_eq!(output, expected);
        assert_eq!(parse_ipv4_packet(&output).unwrap(), packet);
    }

    #[test]
    fn serialises_options_and_payload_but_not_trailing_bytes() {
        let options = [0x01, 0x01, 0x00, 0x00];
        let payload = [0xde, 0xad, 0xbe, 0xef];
        let trailing_bytes = [0xaa, 0xbb, 0xcc];
        let mut packet = serialisable_packet();
        packet.options = &options;
        packet.payload = &payload;
        packet.trailing_bytes = &trailing_bytes;
        packet.protocol = Ipv4Protocol::Unknown(253);
        let mut output = [0xa5; 31];

        let written = packet.write_to(&mut output).unwrap();

        assert_eq!(written, 28);
        assert_eq!(output[0], 0x46);
        assert_eq!(&output[2..4], &28_u16.to_be_bytes());
        assert_eq!(output[9], 253);
        assert_eq!(&output[20..24], &options);
        assert_eq!(&output[24..28], &payload);
        assert_eq!(&output[28..], &[0xa5; 3]);
        assert_eq!(checksum(&output[..24]), 0);

        let reparsed = parse_ipv4_packet(&output[..written]).unwrap();
        assert_eq!(reparsed.options, options);
        assert_eq!(reparsed.payload, payload);
        assert!(reparsed.trailing_bytes.is_empty());
    }

    #[test]
    fn serialiser_rejects_every_short_buffer_without_modifying_it() {
        let options = [0x01, 0x01, 0x00, 0x00];
        let payload = [0xde, 0xad, 0xbe, 0xef];
        let mut packet = serialisable_packet();
        packet.options = &options;
        packet.payload = &payload;
        let required = IPV4_MIN_HEADER_LEN + options.len() + payload.len();

        for length in 0..required {
            let mut output = vec![0xa5; length];
            let original = output.clone();

            assert_eq!(
                packet.write_to(&mut output),
                Err(Ipv4SerialiseError::BufferTooSmall {
                    actual: length,
                    required,
                })
            );
            assert_eq!(output, original);
        }
    }

    #[test]
    fn serialiser_rejects_invalid_field_values_without_modifying_the_buffer() {
        let mut output = [0xa5; IPV4_MIN_HEADER_LEN];
        let original = output;

        let mut packet = serialisable_packet();
        packet.dscp = 64;
        assert_eq!(
            packet.write_to(&mut output),
            Err(Ipv4SerialiseError::DscpOutOfRange { value: 64 })
        );
        assert_eq!(output, original);

        packet = serialisable_packet();
        packet.ecn = 4;
        assert_eq!(
            packet.write_to(&mut output),
            Err(Ipv4SerialiseError::EcnOutOfRange { value: 4 })
        );
        assert_eq!(output, original);

        packet = serialisable_packet();
        packet.fragment_offset = 0x2000;
        assert_eq!(
            packet.write_to(&mut output),
            Err(Ipv4SerialiseError::FragmentOffsetOutOfRange { value: 0x2000 })
        );
        assert_eq!(output, original);
    }

    #[test]
    fn serialiser_rejects_invalid_option_lengths_without_modifying_the_buffer() {
        let unaligned_options = [0; 2];
        let mut packet = serialisable_packet();
        packet.options = &unaligned_options;
        let mut output = [0xa5; 64];
        let original = output;

        assert_eq!(
            packet.write_to(&mut output),
            Err(Ipv4SerialiseError::OptionsNotMultipleOfFour { actual: 2 })
        );
        assert_eq!(output, original);

        let excessive_options = [0; 44];
        packet.options = &excessive_options;
        assert_eq!(
            packet.write_to(&mut output),
            Err(Ipv4SerialiseError::OptionsTooLong {
                actual: 44,
                maximum: 40,
            })
        );
        assert_eq!(output, original);
    }

    #[test]
    fn serialiser_rejects_a_total_length_larger_than_the_wire_field() {
        let payload = vec![0; usize::from(u16::MAX) - IPV4_MIN_HEADER_LEN + 1];
        let mut packet = serialisable_packet();
        packet.payload = &payload;
        let mut output = [0xa5; IPV4_MIN_HEADER_LEN];
        let original = output;

        assert_eq!(
            packet.write_to(&mut output),
            Err(Ipv4SerialiseError::TotalLengthTooLarge {
                actual: usize::from(u16::MAX) + 1,
                maximum: usize::from(u16::MAX),
            })
        );
        assert_eq!(output, original);
    }

    #[test]
    fn converts_protocols_to_their_wire_values() {
        for (protocol, expected) in [
            (Ipv4Protocol::Icmp, 1),
            (Ipv4Protocol::Tcp, 6),
            (Ipv4Protocol::Udp, 17),
            (Ipv4Protocol::Unknown(253), 253),
        ] {
            assert_eq!(protocol.as_u8(), expected);
        }
    }
}
