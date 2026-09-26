use std::{fmt, net::Ipv4Addr};

use crate::checksum::checksum;

pub const TCP_MIN_HEADER_LEN: usize = 20;
pub const TCP_MAX_OPTION_LEN: usize = 40;
const TCP_MIN_DATA_OFFSET: u8 = 5;
const IPV4_TCP_PROTOCOL_NUMBER: u8 = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpFlags(u8);

impl TcpFlags {
    pub const FIN: Self = Self(0x01);
    pub const SYN: Self = Self(0x02);
    pub const RST: Self = Self(0x04);
    pub const PSH: Self = Self(0x08);
    pub const ACK: Self = Self(0x10);
    pub const URG: Self = Self(0x20);
    pub const ECE: Self = Self(0x40);
    pub const CWR: Self = Self(0x80);

    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn contains(self, flag: Self) -> bool {
        self.0 & flag.0 == flag.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpParseError {
    SegmentTooShort { actual: usize, minimum: usize },
    SegmentTooLong { actual: usize, maximum: usize },
    InvalidDataOffset { data_offset: u8, minimum: u8 },
    TruncatedHeader { actual: usize, required: usize },
    InvalidChecksum,
}

impl fmt::Display for TcpParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SegmentTooShort { actual, minimum } => write!(
                formatter,
                "TCP segment is {actual} bytes long; expected at least {minimum} bytes"
            ),
            Self::SegmentTooLong { actual, maximum } => write!(
                formatter,
                "TCP segment is {actual} bytes long; maximum is {maximum} bytes"
            ),
            Self::InvalidDataOffset {
                data_offset,
                minimum,
            } => write!(
                formatter,
                "TCP data offset is {data_offset}; expected at least {minimum}"
            ),
            Self::TruncatedHeader { actual, required } => write!(
                formatter,
                "TCP header requires {required} bytes but only {actual} are available"
            ),
            Self::InvalidChecksum => write!(formatter, "invalid TCP checksum"),
        }
    }
}

impl std::error::Error for TcpParseError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpSegment<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub acknowledgement_number: u32,
    /// The wire value, measured in units of four bytes.
    pub data_offset: u8,
    pub reserved: u8,
    pub flags: TcpFlags,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub options: &'a [u8],
    pub payload: &'a [u8],
}

pub fn parse_tcp_segment(data: &[u8]) -> Result<TcpSegment<'_>, TcpParseError> {
    if data.len() < TCP_MIN_HEADER_LEN {
        return Err(TcpParseError::SegmentTooShort {
            actual: data.len(),
            minimum: TCP_MIN_HEADER_LEN,
        });
    }

    let data_offset = data[12] >> 4;
    if data_offset < TCP_MIN_DATA_OFFSET {
        return Err(TcpParseError::InvalidDataOffset {
            data_offset,
            minimum: TCP_MIN_DATA_OFFSET,
        });
    }

    let header_length = usize::from(data_offset) * 4;
    if data.len() < header_length {
        return Err(TcpParseError::TruncatedHeader {
            actual: data.len(),
            required: header_length,
        });
    }

    Ok(TcpSegment {
        source_port: u16::from_be_bytes([data[0], data[1]]),
        destination_port: u16::from_be_bytes([data[2], data[3]]),
        sequence_number: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
        acknowledgement_number: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
        data_offset,
        reserved: data[12] & 0x0f,
        flags: TcpFlags::from_bits(data[13]),
        window_size: u16::from_be_bytes([data[14], data[15]]),
        checksum: u16::from_be_bytes([data[16], data[17]]),
        urgent_pointer: u16::from_be_bytes([data[18], data[19]]),
        options: &data[TCP_MIN_HEADER_LEN..header_length],
        payload: &data[header_length..],
    })
}

pub fn validate_tcp_checksum(
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    data: &[u8],
) -> Result<(), TcpParseError> {
    // Validate the structure first so callers receive the most useful error and
    // malformed input cannot reach later TCP processing.
    parse_tcp_segment(data)?;

    let length = u16::try_from(data.len()).map_err(|_| TcpParseError::SegmentTooLong {
        actual: data.len(),
        maximum: usize::from(u16::MAX),
    })?;

    if calculate_tcp_checksum(source_ip, destination_ip, length, data) == 0 {
        Ok(())
    } else {
        Err(TcpParseError::InvalidChecksum)
    }
}

fn calculate_tcp_checksum(
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    length: u16,
    segment_bytes: &[u8],
) -> u16 {
    let mut checksum_bytes = Vec::with_capacity(12 + segment_bytes.len());

    // This pseudo-header participates in the checksum but is not transmitted
    // as part of the TCP segment.
    checksum_bytes.extend_from_slice(&source_ip.octets());
    checksum_bytes.extend_from_slice(&destination_ip.octets());
    checksum_bytes.push(0);
    checksum_bytes.push(IPV4_TCP_PROTOCOL_NUMBER);
    checksum_bytes.extend_from_slice(&length.to_be_bytes());
    checksum_bytes.extend_from_slice(segment_bytes);

    checksum(&checksum_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const DESTINATION_IP: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 2);

    const SYN_SEGMENT: [u8; TCP_MIN_HEADER_LEN] = [
        0xc0, 0x00, // source port: 49152
        0x23, 0x28, // destination port: 9000
        0x11, 0x22, 0x33, 0x44, // sequence number
        0x00, 0x00, 0x00, 0x00, // acknowledgement number
        0x50, // data offset: 5, reserved: 0
        0x02, // SYN
        0xff, 0xff, // window size
        0x12, 0x34, // checksum (not validated yet)
        0x00, 0x00, // urgent pointer
    ];

    // The fixed checksum values were calculated independently of the code under test.
    const CHECKSUMMED_SYN: [u8; TCP_MIN_HEADER_LEN] = [
        0xc0, 0x00, 0x23, 0x28, 0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0xff,
        0xff, 0x9c, 0x1c, 0x00, 0x00,
    ];

    const CHECKSUMMED_ODD_PAYLOAD: [u8; TCP_MIN_HEADER_LEN + 3] = [
        0xc0, 0x00, 0x23, 0x28, 0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0xff,
        0xff, 0xba, 0xb3, 0x00, 0x00, b'h', b'e', b'y',
    ];

    const CHECKSUMMED_OPTIONS_AND_PAYLOAD: [u8; TCP_MIN_HEADER_LEN + 4 + 5] = [
        0xc0, 0x00, 0x23, 0x28, 0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x00, 0x00, 0x60, 0x02, 0xff,
        0xff, 0x40, 0x89, 0x00, 0x00, 2, 4, 0x05, 0xb4, b'h', b'e', b'l', b'l', b'o',
    ];

    #[test]
    fn parses_a_minimum_length_syn_segment() {
        assert_eq!(
            parse_tcp_segment(&SYN_SEGMENT),
            Ok(TcpSegment {
                source_port: 49152,
                destination_port: 9000,
                sequence_number: 0x1122_3344,
                acknowledgement_number: 0,
                data_offset: 5,
                reserved: 0,
                flags: TcpFlags::SYN,
                window_size: u16::MAX,
                checksum: 0x1234,
                urgent_pointer: 0,
                options: &[],
                payload: &[],
            })
        );
    }

    #[test]
    fn separates_options_from_payload() {
        let mut data = SYN_SEGMENT.to_vec();
        data[12] = 0x60;
        data.extend_from_slice(&[2, 4, 0x05, 0xb4]); // MSS option: 1460
        data.extend_from_slice(b"hello");

        let parsed = parse_tcp_segment(&data).unwrap();

        assert_eq!(parsed.data_offset, 6);
        assert_eq!(parsed.options, &[2, 4, 0x05, 0xb4]);
        assert_eq!(parsed.payload, b"hello");
    }

    #[test]
    fn decodes_every_control_flag() {
        let mut data = SYN_SEGMENT;
        data[13] = 0xff;

        let flags = parse_tcp_segment(&data).unwrap().flags;

        for flag in [
            TcpFlags::CWR,
            TcpFlags::ECE,
            TcpFlags::URG,
            TcpFlags::ACK,
            TcpFlags::PSH,
            TcpFlags::RST,
            TcpFlags::SYN,
            TcpFlags::FIN,
        ] {
            assert!(flags.contains(flag));
        }
        assert_eq!(flags.bits(), 0xff);
    }

    #[test]
    fn preserves_reserved_bits_without_rejecting_them() {
        let mut data = SYN_SEGMENT;
        data[12] = 0x5f;

        assert_eq!(parse_tcp_segment(&data).unwrap().reserved, 0x0f);
    }

    #[test]
    fn rejects_every_segment_shorter_than_the_minimum_header() {
        for length in 0..TCP_MIN_HEADER_LEN {
            assert_eq!(
                parse_tcp_segment(&SYN_SEGMENT[..length]),
                Err(TcpParseError::SegmentTooShort {
                    actual: length,
                    minimum: TCP_MIN_HEADER_LEN,
                })
            );
        }
    }

    #[test]
    fn rejects_a_data_offset_smaller_than_five() {
        let mut data = SYN_SEGMENT;
        data[12] = 0x40;

        assert_eq!(
            parse_tcp_segment(&data),
            Err(TcpParseError::InvalidDataOffset {
                data_offset: 4,
                minimum: TCP_MIN_DATA_OFFSET,
            })
        );
    }

    #[test]
    fn rejects_a_segment_shorter_than_its_declared_header() {
        let mut data = SYN_SEGMENT;
        data[12] = 0x60;

        assert_eq!(
            parse_tcp_segment(&data),
            Err(TcpParseError::TruncatedHeader {
                actual: TCP_MIN_HEADER_LEN,
                required: 24,
            })
        );
    }

    #[test]
    fn accepts_the_maximum_header_length() {
        let mut data = [0; TCP_MIN_HEADER_LEN + TCP_MAX_OPTION_LEN];
        data[..TCP_MIN_HEADER_LEN].copy_from_slice(&SYN_SEGMENT);
        data[12] = 0xf0;

        let parsed = parse_tcp_segment(&data).unwrap();

        assert_eq!(parsed.data_offset, 15);
        assert_eq!(parsed.options.len(), TCP_MAX_OPTION_LEN);
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn validates_a_minimum_length_segment_checksum() {
        assert_eq!(
            validate_tcp_checksum(SOURCE_IP, DESTINATION_IP, &CHECKSUMMED_SYN),
            Ok(())
        );
    }

    #[test]
    fn validates_an_odd_length_payload_checksum() {
        assert_eq!(
            validate_tcp_checksum(SOURCE_IP, DESTINATION_IP, &CHECKSUMMED_ODD_PAYLOAD),
            Ok(())
        );
    }

    #[test]
    fn checksum_covers_options_and_payload() {
        assert_eq!(
            validate_tcp_checksum(SOURCE_IP, DESTINATION_IP, &CHECKSUMMED_OPTIONS_AND_PAYLOAD,),
            Ok(())
        );
    }

    #[test]
    fn detects_a_changed_payload_byte() {
        let mut data = CHECKSUMMED_ODD_PAYLOAD;
        data[TCP_MIN_HEADER_LEN] ^= 1;

        assert_eq!(
            validate_tcp_checksum(SOURCE_IP, DESTINATION_IP, &data),
            Err(TcpParseError::InvalidChecksum)
        );
    }

    #[test]
    fn detects_a_changed_ip_address() {
        assert_eq!(
            validate_tcp_checksum(SOURCE_IP, Ipv4Addr::new(198, 51, 100, 3), &CHECKSUMMED_SYN,),
            Err(TcpParseError::InvalidChecksum)
        );
    }

    #[test]
    fn does_not_treat_a_zero_checksum_as_omitted() {
        let mut data = CHECKSUMMED_SYN;
        data[16..18].fill(0);

        assert_eq!(
            validate_tcp_checksum(SOURCE_IP, DESTINATION_IP, &data),
            Err(TcpParseError::InvalidChecksum)
        );
    }

    #[test]
    fn checksum_validation_reports_structural_errors_first() {
        assert_eq!(
            validate_tcp_checksum(
                SOURCE_IP,
                DESTINATION_IP,
                &SYN_SEGMENT[..TCP_MIN_HEADER_LEN - 1],
            ),
            Err(TcpParseError::SegmentTooShort {
                actual: TCP_MIN_HEADER_LEN - 1,
                minimum: TCP_MIN_HEADER_LEN,
            })
        );
    }

    #[test]
    fn checksum_rejects_a_segment_larger_than_the_ipv4_length_field() {
        let mut data = vec![0; usize::from(u16::MAX) + 1];
        data[12] = 0x50;

        assert_eq!(
            validate_tcp_checksum(SOURCE_IP, DESTINATION_IP, &data),
            Err(TcpParseError::SegmentTooLong {
                actual: usize::from(u16::MAX) + 1,
                maximum: usize::from(u16::MAX),
            })
        );
    }
}
