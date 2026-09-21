use std::{fmt, net::Ipv4Addr};

use crate::checksum::checksum;

pub const UDP_HEADER_LEN: usize = 8;
const IPV4_UDP_PROTOCOL_NUMBER: u8 = 17;

// | Bytes | Field |
// |---|---|
// | 0–1 | Source port |
// | 2–3 | Destination port |
// | 4–5 | Length, including the eight-byte header |
// | 6–7 | Checksum |
// | 8 onward | Application data |

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpDatagram<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UdpParseError {
    DatagramTooShort { actual: usize, minimum: usize },
    InvalidLength { declared: usize, minimum: usize },
    TruncatedDatagram { actual: usize, declared: usize },
    InvalidChecksum,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UdpSerialiseError {
    BufferTooSmall { actual: usize, required: usize },
    DatagramTooLong { actual: usize, maximum: usize },
}

impl fmt::Display for UdpSerialiseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooSmall { actual, required } => write!(
                formatter,
                "output buffer is {actual} bytes long; {required} bytes are required"
            ),
            Self::DatagramTooLong { actual, maximum } => write!(
                formatter,
                "UDP datagram is {actual} bytes long; maximum is {maximum} bytes"
            ),
        }
    }
}

impl std::error::Error for UdpSerialiseError {}

impl fmt::Display for UdpParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DatagramTooShort { actual, minimum } => write!(
                formatter,
                "UDP datagram is {actual} bytes long; expected at least {minimum} bytes"
            ),
            Self::InvalidLength { declared, minimum } => write!(
                formatter,
                "UDP length field is {declared}; expected at least {minimum} bytes"
            ),
            Self::TruncatedDatagram { actual, declared } => write!(
                formatter,
                "UDP datagram declares {declared} bytes but only {actual} are available"
            ),
            Self::InvalidChecksum => write!(formatter, "invalid UDP checksum"),
        }
    }
}

impl std::error::Error for UdpParseError {}

pub fn parse_udp_datagram(data: &[u8]) -> Result<UdpDatagram<'_>, UdpParseError> {
    if data.len() < UDP_HEADER_LEN {
        return Err(UdpParseError::DatagramTooShort {
            actual: data.len(),
            minimum: UDP_HEADER_LEN,
        });
    }
    let source_port = u16::from_be_bytes([data[0], data[1]]);
    let destination_port = u16::from_be_bytes([data[2], data[3]]);
    let length = u16::from_be_bytes([data[4], data[5]]);
    let checksum = u16::from_be_bytes([data[6], data[7]]);
    let declared = usize::from(length);

    if declared < UDP_HEADER_LEN {
        return Err(UdpParseError::InvalidLength {
            declared,
            minimum: UDP_HEADER_LEN,
        });
    }
    if declared > data.len() {
        return Err(UdpParseError::TruncatedDatagram {
            actual: data.len(),
            declared,
        });
    }

    let payload = &data[UDP_HEADER_LEN..declared];

    Ok(UdpDatagram {
        source_port,
        destination_port,
        length,
        checksum,
        payload,
    })
}

/// Checks the IPv4 UDP checksum using the IP addresses from the enclosing packet.
///
/// A zero checksum field means the sender omitted the checksum, which IPv4 allows.
/// Bytes after the UDP length field are not part of the checksum.
pub fn validate_udp_checksum(
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    data: &[u8],
) -> Result<(), UdpParseError> {
    let datagram = parse_udp_datagram(data)?;
    if datagram.checksum == 0 {
        return Ok(());
    }

    let datagram_length = usize::from(datagram.length);
    if calculate_udp_checksum(
        source_ip,
        destination_ip,
        datagram.length,
        &data[..datagram_length],
    ) == 0
    {
        Ok(())
    } else {
        Err(UdpParseError::InvalidChecksum)
    }
}

pub fn serialise_udp_datagram(
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
    output: &mut [u8],
) -> Result<usize, UdpSerialiseError> {
    let required = UDP_HEADER_LEN + payload.len();
    if required > usize::from(u16::MAX) {
        return Err(UdpSerialiseError::DatagramTooLong {
            actual: required,
            maximum: usize::from(u16::MAX),
        });
    }
    if output.len() < required {
        return Err(UdpSerialiseError::BufferTooSmall {
            actual: output.len(),
            required,
        });
    }

    let length = required as u16;
    output[0..2].copy_from_slice(&source_port.to_be_bytes());
    output[2..4].copy_from_slice(&destination_port.to_be_bytes());
    output[4..6].copy_from_slice(&length.to_be_bytes());
    output[6..8].fill(0);
    output[UDP_HEADER_LEN..required].copy_from_slice(payload);

    let calculated = calculate_udp_checksum(source_ip, destination_ip, length, &output[..required]);
    // Zero on the IPv4 wire means "checksum omitted", so calculated zero is
    // represented by the one's-complement equivalent value, all ones.
    let transmitted = if calculated == 0 {
        u16::MAX
    } else {
        calculated
    };
    output[6..8].copy_from_slice(&transmitted.to_be_bytes());

    Ok(required)
}

fn calculate_udp_checksum(
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    length: u16,
    datagram_bytes: &[u8],
) -> u16 {
    let mut checksum_bytes = Vec::with_capacity(12 + datagram_bytes.len());

    // The 12-byte pseudo-header participates in the checksum but is not sent.
    checksum_bytes.extend_from_slice(&source_ip.octets());
    checksum_bytes.extend_from_slice(&destination_ip.octets());
    checksum_bytes.push(0);
    checksum_bytes.push(IPV4_UDP_PROTOCOL_NUMBER);
    checksum_bytes.extend_from_slice(&length.to_be_bytes());
    checksum_bytes.extend_from_slice(datagram_bytes);

    checksum(&checksum_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const DESTINATION_IP: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 2);

    const DATAGRAM: [u8; 12] = [
        0x1f, 0x90, // source port: 8080
        0x23, 0x28, // destination port: 9000
        0x00, 0x0c, // length: 12 bytes
        0x00, 0x00, // no UDP checksum (allowed with IPv4)
        b'p', b'i', b'n', b'g',
    ];

    // These include fixed, precomputed checksums, so validation is not tested
    // against a value produced by the implementation under test.
    const CHECKSUMMED_EVEN: [u8; 12] = [
        0x1f, 0x90, 0x23, 0x28, 0x00, 0x0c, 0xf2, 0x15, b'p', b'i', b'n', b'g',
    ];
    const CHECKSUMMED_ODD: [u8; 11] = [
        0x1f, 0x90, 0x23, 0x28, 0x00, 0x0b, 0xef, 0x82, b'h', b'e', b'y',
    ];

    #[test]
    fn parses_a_datagram() {
        assert_eq!(
            parse_udp_datagram(&DATAGRAM),
            Ok(UdpDatagram {
                source_port: 8080,
                destination_port: 9000,
                length: 12,
                checksum: 0,
                payload: b"ping",
            })
        );
    }

    #[test]
    fn accepts_an_empty_payload() {
        let mut data = DATAGRAM[..UDP_HEADER_LEN].to_vec();
        data[4..6].copy_from_slice(&(UDP_HEADER_LEN as u16).to_be_bytes());

        assert_eq!(parse_udp_datagram(&data).unwrap().payload, b"");
    }

    #[test]
    fn rejects_every_input_shorter_than_the_header() {
        for length in 0..UDP_HEADER_LEN {
            assert_eq!(
                parse_udp_datagram(&DATAGRAM[..length]),
                Err(UdpParseError::DatagramTooShort {
                    actual: length,
                    minimum: UDP_HEADER_LEN,
                })
            );
        }
    }

    #[test]
    fn rejects_a_length_smaller_than_the_header() {
        for declared in [0_u16, 7] {
            let mut data = DATAGRAM;
            data[4..6].copy_from_slice(&declared.to_be_bytes());

            assert_eq!(
                parse_udp_datagram(&data),
                Err(UdpParseError::InvalidLength {
                    declared: usize::from(declared),
                    minimum: UDP_HEADER_LEN,
                })
            );
        }
    }

    #[test]
    fn rejects_a_length_larger_than_the_available_bytes() {
        let mut data = DATAGRAM;
        data[4..6].copy_from_slice(&13_u16.to_be_bytes());

        assert_eq!(
            parse_udp_datagram(&data),
            Err(UdpParseError::TruncatedDatagram {
                actual: 12,
                declared: 13,
            })
        );
    }

    #[test]
    fn ignores_bytes_after_the_declared_datagram() {
        let mut data = DATAGRAM.to_vec();
        data.extend_from_slice(b"extra");

        assert_eq!(parse_udp_datagram(&data).unwrap().payload, b"ping");
    }

    #[test]
    fn preserves_a_nonzero_checksum_without_validating_it_yet() {
        let mut data = DATAGRAM;
        data[6..8].copy_from_slice(&0x1234_u16.to_be_bytes());

        assert_eq!(parse_udp_datagram(&data).unwrap().checksum, 0x1234);
    }

    #[test]
    fn validates_a_checksum_with_an_even_length_payload() {
        assert_eq!(
            validate_udp_checksum(SOURCE_IP, DESTINATION_IP, &CHECKSUMMED_EVEN),
            Ok(())
        );
    }

    #[test]
    fn validates_a_checksum_with_an_odd_length_payload() {
        assert_eq!(
            validate_udp_checksum(SOURCE_IP, DESTINATION_IP, &CHECKSUMMED_ODD),
            Ok(())
        );
    }

    #[test]
    fn detects_a_changed_payload_byte() {
        let mut data = CHECKSUMMED_EVEN;
        data[8] ^= 1;

        assert_eq!(
            validate_udp_checksum(SOURCE_IP, DESTINATION_IP, &data),
            Err(UdpParseError::InvalidChecksum)
        );
    }

    #[test]
    fn detects_a_changed_ip_address() {
        assert_eq!(
            validate_udp_checksum(SOURCE_IP, Ipv4Addr::new(198, 51, 100, 3), &CHECKSUMMED_EVEN),
            Err(UdpParseError::InvalidChecksum)
        );
    }

    #[test]
    fn accepts_a_zero_checksum_for_ipv4() {
        assert_eq!(
            validate_udp_checksum(SOURCE_IP, DESTINATION_IP, &DATAGRAM),
            Ok(())
        );
    }

    #[test]
    fn ignores_bytes_after_the_declared_length_when_validating() {
        let mut data = CHECKSUMMED_EVEN.to_vec();
        data.extend_from_slice(b"padding");

        assert_eq!(
            validate_udp_checksum(SOURCE_IP, DESTINATION_IP, &data),
            Ok(())
        );
    }

    #[test]
    fn rejects_a_malformed_length_even_when_the_checksum_is_omitted() {
        let mut data = DATAGRAM;
        data[4..6].copy_from_slice(&13_u16.to_be_bytes());

        assert_eq!(
            validate_udp_checksum(SOURCE_IP, DESTINATION_IP, &data),
            Err(UdpParseError::TruncatedDatagram {
                actual: 12,
                declared: 13,
            })
        );
    }

    #[test]
    fn serialises_the_exact_datagram_and_checksum() {
        let mut output = [0; CHECKSUMMED_EVEN.len()];

        let written =
            serialise_udp_datagram(SOURCE_IP, DESTINATION_IP, 8080, 9000, b"ping", &mut output)
                .unwrap();

        assert_eq!(written, CHECKSUMMED_EVEN.len());
        assert_eq!(output, CHECKSUMMED_EVEN);
    }

    #[test]
    fn serialises_an_odd_length_payload() {
        let mut output = [0; CHECKSUMMED_ODD.len()];

        let written =
            serialise_udp_datagram(SOURCE_IP, DESTINATION_IP, 8080, 9000, b"hey", &mut output)
                .unwrap();

        assert_eq!(written, CHECKSUMMED_ODD.len());
        assert_eq!(output, CHECKSUMMED_ODD);
    }

    #[test]
    fn serialised_datagram_round_trips_through_parser_and_validator() {
        let mut output = [0; 12];
        serialise_udp_datagram(SOURCE_IP, DESTINATION_IP, 8080, 9000, b"ping", &mut output)
            .unwrap();

        let parsed = parse_udp_datagram(&output).unwrap();
        assert_eq!(parsed.source_port, 8080);
        assert_eq!(parsed.destination_port, 9000);
        assert_eq!(parsed.length, 12);
        assert_eq!(parsed.payload, b"ping");
        assert_ne!(parsed.checksum, 0);
        assert_eq!(
            validate_udp_checksum(SOURCE_IP, DESTINATION_IP, &output),
            Ok(())
        );
    }

    #[test]
    fn serialiser_rejects_every_short_buffer_without_modifying_it() {
        let required = UDP_HEADER_LEN + 4;

        for length in 0..required {
            let mut output = vec![0xa5; length];
            let before = output.clone();

            assert_eq!(
                serialise_udp_datagram(SOURCE_IP, DESTINATION_IP, 8080, 9000, b"ping", &mut output,),
                Err(UdpSerialiseError::BufferTooSmall {
                    actual: length,
                    required,
                })
            );
            assert_eq!(output, before);
        }
    }

    #[test]
    fn serialiser_rejects_a_datagram_larger_than_the_length_field() {
        let payload = vec![0; usize::from(u16::MAX) - UDP_HEADER_LEN + 1];
        let mut output = [];

        assert_eq!(
            serialise_udp_datagram(SOURCE_IP, DESTINATION_IP, 8080, 9000, &payload, &mut output,),
            Err(UdpSerialiseError::DatagramTooLong {
                actual: usize::from(u16::MAX) + 1,
                maximum: usize::from(u16::MAX),
            })
        );
    }

    #[test]
    fn transmits_a_calculated_zero_checksum_as_all_ones() {
        // For these addresses and ports, this payload makes the calculated
        // one's-complement checksum zero.
        let mut output = [0; UDP_HEADER_LEN + 2];
        serialise_udp_datagram(
            SOURCE_IP,
            DESTINATION_IP,
            8080,
            9000,
            &[0xd0, 0xea],
            &mut output,
        )
        .unwrap();

        assert_eq!(&output[6..8], &[0xff, 0xff]);
        assert_eq!(
            validate_udp_checksum(SOURCE_IP, DESTINATION_IP, &output),
            Ok(())
        );
    }

    #[test]
    fn serialiser_does_not_modify_bytes_after_the_datagram() {
        let mut output = [0xa5; 16];

        let written =
            serialise_udp_datagram(SOURCE_IP, DESTINATION_IP, 8080, 9000, b"ping", &mut output)
                .unwrap();

        assert_eq!(written, 12);
        assert_eq!(&output[12..], &[0xa5; 4]);
    }
}
