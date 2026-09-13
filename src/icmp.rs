use std::fmt;

use crate::{SerialiseError, checksum::checksum};

pub const ICMP_HEADER_LEN: usize = 4;
pub const ICMP_ECHO_HEADER_LEN: usize = 8;

const ECHO_REPLY_TYPE: u8 = 0;
const ECHO_REQUEST_TYPE: u8 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IcmpEchoMessage<'a> {
    pub identifier: u16,
    pub sequence_number: u16,
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IcmpMessage<'a> {
    EchoRequest(IcmpEchoMessage<'a>),
    EchoReply(IcmpEchoMessage<'a>),
    Unknown {
        message_type: u8,
        code: u8,
        body: &'a [u8],
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IcmpParseError {
    MessageTooShort { actual: usize, minimum: usize },
    EchoMessageTooShort { actual: usize, minimum: usize },
    InvalidEchoCode { message_type: u8, code: u8 },
    InvalidChecksum,
}

impl fmt::Display for IcmpParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MessageTooShort { actual, minimum } => write!(
                formatter,
                "ICMP message is {actual} bytes long; expected at least {minimum} bytes"
            ),
            Self::EchoMessageTooShort { actual, minimum } => write!(
                formatter,
                "ICMP Echo message is {actual} bytes long; expected at least {minimum} bytes"
            ),
            Self::InvalidEchoCode { message_type, code } => write!(
                formatter,
                "ICMP Echo message type {message_type} has code {code}; expected zero"
            ),
            Self::InvalidChecksum => write!(formatter, "invalid ICMP checksum"),
        }
    }
}

impl std::error::Error for IcmpParseError {}

pub fn parse_icmp_message(data: &[u8]) -> Result<IcmpMessage<'_>, IcmpParseError> {
    if data.len() < ICMP_HEADER_LEN {
        return Err(IcmpParseError::MessageTooShort {
            actual: data.len(),
            minimum: ICMP_HEADER_LEN,
        });
    }

    let message_type = data[0];
    let code = data[1];

    if matches!(message_type, ECHO_REPLY_TYPE | ECHO_REQUEST_TYPE) {
        if code != 0 {
            return Err(IcmpParseError::InvalidEchoCode { message_type, code });
        }
        if data.len() < ICMP_ECHO_HEADER_LEN {
            return Err(IcmpParseError::EchoMessageTooShort {
                actual: data.len(),
                minimum: ICMP_ECHO_HEADER_LEN,
            });
        }
    }

    if checksum(data) != 0 {
        return Err(IcmpParseError::InvalidChecksum);
    }

    match message_type {
        ECHO_REQUEST_TYPE => Ok(IcmpMessage::EchoRequest(IcmpEchoMessage {
            identifier: u16::from_be_bytes([data[4], data[5]]),
            sequence_number: u16::from_be_bytes([data[6], data[7]]),
            payload: &data[ICMP_ECHO_HEADER_LEN..],
        })),
        ECHO_REPLY_TYPE => Ok(IcmpMessage::EchoReply(IcmpEchoMessage {
            identifier: u16::from_be_bytes([data[4], data[5]]),
            sequence_number: u16::from_be_bytes([data[6], data[7]]),
            payload: &data[ICMP_ECHO_HEADER_LEN..],
        })),
        _ => Ok(IcmpMessage::Unknown {
            message_type,
            code,
            body: &data[ICMP_HEADER_LEN..],
        }),
    }
}

impl IcmpMessage<'_> {
    pub fn write_to(&self, output: &mut [u8]) -> Result<usize, SerialiseError> {
        let required = match self {
            Self::EchoRequest(message) | Self::EchoReply(message) => {
                ICMP_ECHO_HEADER_LEN + message.payload.len()
            }
            Self::Unknown { body, .. } => ICMP_HEADER_LEN + body.len(),
        };

        if output.len() < required {
            return Err(SerialiseError::BufferTooSmall {
                actual: output.len(),
                required,
            });
        }

        match self {
            Self::EchoRequest(message) => {
                output[0] = ECHO_REQUEST_TYPE;
                output[1] = 0;
                output[4..6].copy_from_slice(&message.identifier.to_be_bytes());
                output[6..8].copy_from_slice(&message.sequence_number.to_be_bytes());
                output[ICMP_ECHO_HEADER_LEN..required].copy_from_slice(message.payload);
            }
            Self::EchoReply(message) => {
                output[0] = ECHO_REPLY_TYPE;
                output[1] = 0;
                output[4..6].copy_from_slice(&message.identifier.to_be_bytes());
                output[6..8].copy_from_slice(&message.sequence_number.to_be_bytes());
                output[ICMP_ECHO_HEADER_LEN..required].copy_from_slice(message.payload);
            }
            Self::Unknown {
                message_type,
                code,
                body,
            } => {
                output[0] = *message_type;
                output[1] = *code;
                output[ICMP_HEADER_LEN..required].copy_from_slice(body);
            }
        }

        output[2..4].fill(0);
        let checksum_value = checksum(&output[..required]);
        output[2..4].copy_from_slice(&checksum_value.to_be_bytes());

        Ok(required)
    }
}

pub fn build_echo_reply<'a>(request: &IcmpMessage<'a>) -> Option<IcmpMessage<'a>> {
    match request {
        IcmpMessage::EchoRequest(message) => Some(IcmpMessage::EchoReply(*message)),
        IcmpMessage::EchoReply(_) | IcmpMessage::Unknown { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ECHO_REQUEST: [u8; 12] = [
        8, 0, 0x48, 0x2d, // type, code, checksum
        0x12, 0x34, 0x00, 0x01, // identifier and sequence number
        0xde, 0xad, 0xbe, 0xef, // payload
    ];

    const ECHO_REPLY: [u8; 12] = [
        0, 0, 0x50, 0x2d, // type, code, checksum
        0x12, 0x34, 0x00, 0x01, // identifier and sequence number
        0xde, 0xad, 0xbe, 0xef, // payload
    ];

    fn echo_request() -> IcmpMessage<'static> {
        IcmpMessage::EchoRequest(IcmpEchoMessage {
            identifier: 0x1234,
            sequence_number: 1,
            payload: &[0xde, 0xad, 0xbe, 0xef],
        })
    }

    fn update_checksum(message: &mut [u8]) {
        message[2..4].fill(0);
        let value = checksum(message);
        message[2..4].copy_from_slice(&value.to_be_bytes());
    }

    #[test]
    fn parses_an_echo_request() {
        assert_eq!(parse_icmp_message(&ECHO_REQUEST).unwrap(), echo_request());
    }

    #[test]
    fn parses_an_echo_reply() {
        assert_eq!(
            parse_icmp_message(&ECHO_REPLY).unwrap(),
            IcmpMessage::EchoReply(IcmpEchoMessage {
                identifier: 0x1234,
                sequence_number: 1,
                payload: &[0xde, 0xad, 0xbe, 0xef],
            })
        );
    }

    #[test]
    fn rejects_every_message_shorter_than_the_common_header() {
        for length in 0..ICMP_HEADER_LEN {
            assert_eq!(
                parse_icmp_message(&[0; ICMP_HEADER_LEN][..length]),
                Err(IcmpParseError::MessageTooShort {
                    actual: length,
                    minimum: ICMP_HEADER_LEN,
                })
            );
        }
    }

    #[test]
    fn rejects_a_truncated_echo_message() {
        for length in ICMP_HEADER_LEN..ICMP_ECHO_HEADER_LEN {
            let mut message = [0; ICMP_ECHO_HEADER_LEN];
            message[0] = ECHO_REQUEST_TYPE;

            assert_eq!(
                parse_icmp_message(&message[..length]),
                Err(IcmpParseError::EchoMessageTooShort {
                    actual: length,
                    minimum: ICMP_ECHO_HEADER_LEN,
                })
            );
        }
    }

    #[test]
    fn rejects_a_nonzero_echo_code() {
        let mut message = ECHO_REQUEST;
        message[1] = 1;
        update_checksum(&mut message);

        assert_eq!(
            parse_icmp_message(&message),
            Err(IcmpParseError::InvalidEchoCode {
                message_type: ECHO_REQUEST_TYPE,
                code: 1,
            })
        );
    }

    #[test]
    fn rejects_an_invalid_checksum() {
        let mut message = ECHO_REQUEST;
        message[8] ^= 1;

        assert_eq!(
            parse_icmp_message(&message),
            Err(IcmpParseError::InvalidChecksum)
        );
    }

    #[test]
    fn preserves_an_unknown_type_code_and_body() {
        let mut message = [3, 1, 0, 0, 0xde, 0xad, 0xbe, 0xef];
        update_checksum(&mut message);

        let parsed = parse_icmp_message(&message).unwrap();

        assert_eq!(
            parsed,
            IcmpMessage::Unknown {
                message_type: 3,
                code: 1,
                body: &[0xde, 0xad, 0xbe, 0xef],
            }
        );
        let IcmpMessage::Unknown { body, .. } = parsed else {
            panic!("expected an unknown ICMP message");
        };
        assert_eq!(body.as_ptr(), message[ICMP_HEADER_LEN..].as_ptr());
    }

    #[test]
    fn serialises_the_exact_echo_request() {
        let mut output = [0; ECHO_REQUEST.len()];

        let written = echo_request().write_to(&mut output).unwrap();

        assert_eq!(written, ECHO_REQUEST.len());
        assert_eq!(output, ECHO_REQUEST);
    }

    #[test]
    fn builds_and_serialises_the_exact_echo_reply() {
        let request = parse_icmp_message(&ECHO_REQUEST).unwrap();
        let reply = build_echo_reply(&request).unwrap();
        let mut output = [0; ECHO_REPLY.len()];

        let written = reply.write_to(&mut output).unwrap();

        assert_eq!(written, ECHO_REPLY.len());
        assert_eq!(output, ECHO_REPLY);
        assert_eq!(parse_icmp_message(&output).unwrap(), reply);
    }

    #[test]
    fn does_not_build_a_reply_to_a_reply_or_unknown_message() {
        let reply = parse_icmp_message(&ECHO_REPLY).unwrap();
        let unknown = IcmpMessage::Unknown {
            message_type: 3,
            code: 1,
            body: &[],
        };

        assert_eq!(build_echo_reply(&reply), None);
        assert_eq!(build_echo_reply(&unknown), None);
    }

    #[test]
    fn serialiser_rejects_every_short_buffer_without_modifying_it() {
        let message = echo_request();

        for length in 0..ECHO_REQUEST.len() {
            let mut output = vec![0xa5; length];
            let original = output.clone();

            assert_eq!(
                message.write_to(&mut output),
                Err(SerialiseError::BufferTooSmall {
                    actual: length,
                    required: ECHO_REQUEST.len(),
                })
            );
            assert_eq!(output, original);
        }
    }

    #[test]
    fn unknown_message_round_trips_through_the_serialiser() {
        let message = IcmpMessage::Unknown {
            message_type: 3,
            code: 1,
            body: &[0xde, 0xad, 0xbe, 0xef],
        };
        let mut output = [0; 8];

        message.write_to(&mut output).unwrap();

        assert_eq!(parse_icmp_message(&output).unwrap(), message);
    }

    #[test]
    fn checksums_an_odd_length_echo_payload() {
        let message = IcmpMessage::EchoRequest(IcmpEchoMessage {
            identifier: 7,
            sequence_number: 9,
            payload: &[1, 2, 3],
        });
        let mut output = [0; 11];

        message.write_to(&mut output).unwrap();

        assert_eq!(checksum(&output), 0);
        assert_eq!(parse_icmp_message(&output).unwrap(), message);
    }
}
