use std::{io, time::Instant};

use crate::{
    ETHERNET_HEADER_LEN,
    device::EthernetDevice,
    interface::{InterfaceError, NetworkInterface},
};

/// Enough space for an Ethernet header followed by the largest possible IPv4 packet.
/// Ethernet frame check sequence bytes are supplied and consumed by the device, not this stack.
pub const DEFAULT_RECEIVE_BUFFER_LEN: usize = ETHERNET_HEADER_LEN + u16::MAX as usize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunOutcome {
    Ignored {
        received: usize,
    },
    ReplyTransmitted {
        received: usize,
        transmitted: usize,
    },
    MalformedFrame {
        received: usize,
        error: InterfaceError,
    },
}

pub fn run_once<D: EthernetDevice + ?Sized>(
    device: &mut D,
    interface: &mut NetworkInterface,
    receive_buffer: &mut [u8],
) -> io::Result<RunOutcome> {
    run_once_at(device, interface, receive_buffer, Instant::now())
}

pub fn run_once_at<D: EthernetDevice + ?Sized>(
    device: &mut D,
    interface: &mut NetworkInterface,
    receive_buffer: &mut [u8],
    now: Instant,
) -> io::Result<RunOutcome> {
    let received = device.receive(receive_buffer)?;
    if received == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Ethernet device reached the end of its input stream",
        ));
    }
    let Some(frame) = receive_buffer.get(..received) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Ethernet device reported {received} bytes but the receive buffer holds only {}",
                receive_buffer.len()
            ),
        ));
    };

    match interface.process_frame_at(frame, now) {
        Ok(Some(reply)) => {
            let transmitted = reply.len();
            device.transmit(&reply)?;
            Ok(RunOutcome::ReplyTransmitted {
                received,
                transmitted,
            })
        }
        Ok(None) => Ok(RunOutcome::Ignored { received }),
        Err(error) => Ok(RunOutcome::MalformedFrame { received, error }),
    }
}

pub fn run<D: EthernetDevice + ?Sized>(
    device: &mut D,
    interface: &mut NetworkInterface,
) -> io::Result<()> {
    run_with_observer(device, interface, |_| {})
}

pub fn run_with_observer<D, F>(
    device: &mut D,
    interface: &mut NetworkInterface,
    mut observer: F,
) -> io::Result<()>
where
    D: EthernetDevice + ?Sized,
    F: FnMut(RunOutcome),
{
    let mut receive_buffer = vec![0; DEFAULT_RECEIVE_BUFFER_LEN];

    loop {
        match run_once(device, interface, &mut receive_buffer) {
            Ok(outcome) => observer(outcome),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::net::Ipv4Addr;

    use super::*;
    use crate::{
        EtherType, EthernetFrame, MacAddress,
        arp::{ARP_HEADER_LEN, ArpOperation, ArpPacket, build_request},
        icmp::{ICMP_ECHO_HEADER_LEN, IcmpEchoMessage, IcmpMessage, parse_icmp_message},
        ipv4::{IPV4_MIN_HEADER_LEN, Ipv4Packet, Ipv4Protocol, parse_ipv4_packet},
        parse_eth_frame,
    };

    const LOCAL_MAC: MacAddress = MacAddress::new([0x02, 0, 0, 0, 0, 1]);
    const REMOTE_MAC: MacAddress = MacAddress::new([0x02, 0, 0, 0, 0, 2]);
    const LOCAL_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
    const REMOTE_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

    #[derive(Debug, Default)]
    struct MemoryDevice {
        received_frames: VecDeque<io::Result<Vec<u8>>>,
        transmitted_frames: Vec<Vec<u8>>,
        transmit_error: Option<io::Error>,
    }

    impl MemoryDevice {
        fn with_frame(frame: Vec<u8>) -> Self {
            Self {
                received_frames: VecDeque::from([Ok(frame)]),
                transmitted_frames: Vec::new(),
                transmit_error: None,
            }
        }

        fn with_receive_error(kind: io::ErrorKind) -> Self {
            Self {
                received_frames: VecDeque::from([Err(io::Error::from(kind))]),
                transmitted_frames: Vec::new(),
                transmit_error: None,
            }
        }
    }

    impl EthernetDevice for MemoryDevice {
        fn receive(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let result = self
                .received_frames
                .pop_front()
                .unwrap_or_else(|| Err(io::Error::from(io::ErrorKind::WouldBlock)));
            let frame = result?;

            if frame.len() > buffer.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "memory device receive buffer is too small",
                ));
            }

            buffer[..frame.len()].copy_from_slice(&frame);
            Ok(frame.len())
        }

        fn transmit(&mut self, frame: &[u8]) -> io::Result<()> {
            if let Some(error) = self.transmit_error.take() {
                return Err(error);
            }

            self.transmitted_frames.push(frame.to_vec());
            Ok(())
        }
    }

    fn interface() -> NetworkInterface {
        NetworkInterface::new(LOCAL_MAC, LOCAL_IP)
    }

    fn wrap_ethernet(ether_type: EtherType, payload: &[u8]) -> Vec<u8> {
        let frame = EthernetFrame {
            destination_mac: match ether_type {
                EtherType::Arp => MacAddress::BROADCAST,
                _ => LOCAL_MAC,
            },
            source_mac: REMOTE_MAC,
            ether_type,
            payload,
        };
        let mut bytes = vec![0; ETHERNET_HEADER_LEN + payload.len()];
        frame.write_to(&mut bytes).unwrap();
        bytes
    }

    fn arp_request_frame() -> Vec<u8> {
        let request = build_request(LOCAL_IP, REMOTE_MAC, REMOTE_IP);
        let mut arp_bytes = [0; ARP_HEADER_LEN];
        request.write_to(&mut arp_bytes).unwrap();
        wrap_ethernet(EtherType::Arp, &arp_bytes)
    }

    fn echo_request_frame() -> Vec<u8> {
        let request = IcmpMessage::EchoRequest(IcmpEchoMessage {
            identifier: 0x1234,
            sequence_number: 7,
            payload: &[0xde, 0xad, 0xbe, 0xef],
        });
        let mut icmp_bytes = [0; ICMP_ECHO_HEADER_LEN + 4];
        request.write_to(&mut icmp_bytes).unwrap();

        let ipv4 = Ipv4Packet {
            dscp: 0,
            ecn: 0,
            identification: 0xabcd,
            ttl: 64,
            protocol: Ipv4Protocol::Icmp,
            dont_fragment: false,
            more_fragments: false,
            fragment_offset: 0,
            source: REMOTE_IP,
            destination: LOCAL_IP,
            options: &[],
            payload: &icmp_bytes,
            trailing_bytes: &[],
        };
        let mut ipv4_bytes = vec![0; IPV4_MIN_HEADER_LEN + icmp_bytes.len()];
        ipv4.write_to(&mut ipv4_bytes).unwrap();
        wrap_ethernet(EtherType::Ipv4, &ipv4_bytes)
    }

    #[test]
    fn receives_an_arp_request_and_transmits_its_reply() {
        let request = arp_request_frame();
        let mut device = MemoryDevice::with_frame(request.clone());
        let mut interface = interface();
        let mut receive_buffer = [0; 128];

        let outcome = run_once_at(
            &mut device,
            &mut interface,
            &mut receive_buffer,
            Instant::now(),
        )
        .unwrap();

        assert_eq!(
            outcome,
            RunOutcome::ReplyTransmitted {
                received: request.len(),
                transmitted: ETHERNET_HEADER_LEN + ARP_HEADER_LEN,
            }
        );
        assert_eq!(device.transmitted_frames.len(), 1);
        let ethernet = parse_eth_frame(&device.transmitted_frames[0]).unwrap();
        assert_eq!(ethernet.destination_mac, REMOTE_MAC);
        assert_eq!(ethernet.source_mac, LOCAL_MAC);
        let arp = ArpPacket::parse(ethernet.payload).unwrap();
        assert_eq!(arp.operation, ArpOperation::Reply);
        assert_eq!(arp.sender_ip, LOCAL_IP);
        assert_eq!(arp.target_ip, REMOTE_IP);
    }

    #[test]
    fn receives_an_echo_request_and_transmits_its_reply() {
        let request = echo_request_frame();
        let mut device = MemoryDevice::with_frame(request.clone());
        let mut interface = interface();
        let mut receive_buffer = [0; 128];

        let outcome = run_once_at(
            &mut device,
            &mut interface,
            &mut receive_buffer,
            Instant::now(),
        )
        .unwrap();

        assert_eq!(
            outcome,
            RunOutcome::ReplyTransmitted {
                received: request.len(),
                transmitted: request.len(),
            }
        );
        assert_eq!(device.transmitted_frames.len(), 1);
        let ethernet = parse_eth_frame(&device.transmitted_frames[0]).unwrap();
        let ipv4 = parse_ipv4_packet(ethernet.payload).unwrap();
        let reply = parse_icmp_message(ipv4.payload).unwrap();
        assert!(matches!(reply, IcmpMessage::EchoReply(_)));
    }

    #[test]
    fn ignored_frames_are_not_transmitted() {
        let frame = wrap_ethernet(EtherType::Unknown(0x88b5), &[0xde, 0xad]);
        let mut device = MemoryDevice::with_frame(frame.clone());
        let mut interface = interface();
        let mut receive_buffer = [0; 64];

        let outcome = run_once_at(
            &mut device,
            &mut interface,
            &mut receive_buffer,
            Instant::now(),
        )
        .unwrap();

        assert_eq!(
            outcome,
            RunOutcome::Ignored {
                received: frame.len()
            }
        );
        assert!(device.transmitted_frames.is_empty());
    }

    #[test]
    fn malformed_frames_do_not_prevent_the_next_frame_from_being_processed() {
        let valid = arp_request_frame();
        let mut device = MemoryDevice {
            received_frames: VecDeque::from([Ok(vec![0; 3]), Ok(valid)]),
            transmitted_frames: Vec::new(),
            transmit_error: None,
        };
        let mut interface = interface();
        let mut receive_buffer = [0; 128];

        let first = run_once_at(
            &mut device,
            &mut interface,
            &mut receive_buffer,
            Instant::now(),
        )
        .unwrap();
        let second = run_once_at(
            &mut device,
            &mut interface,
            &mut receive_buffer,
            Instant::now(),
        )
        .unwrap();

        assert!(matches!(
            first,
            RunOutcome::MalformedFrame { received: 3, .. }
        ));
        assert!(matches!(second, RunOutcome::ReplyTransmitted { .. }));
        assert_eq!(device.transmitted_frames.len(), 1);
    }

    #[test]
    fn receive_errors_are_propagated() {
        let mut device = MemoryDevice::with_receive_error(io::ErrorKind::ConnectionReset);
        let mut interface = interface();
        let mut receive_buffer = [0; 64];

        let error = run_once_at(
            &mut device,
            &mut interface,
            &mut receive_buffer,
            Instant::now(),
        )
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    }

    #[test]
    fn a_zero_byte_receive_is_reported_as_end_of_input() {
        let mut device = MemoryDevice::with_frame(Vec::new());
        let mut interface = interface();
        let mut receive_buffer = [0; 64];

        let error = run_once_at(
            &mut device,
            &mut interface,
            &mut receive_buffer,
            Instant::now(),
        )
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert!(device.transmitted_frames.is_empty());
    }

    #[test]
    fn transmit_errors_are_propagated_without_recording_a_frame() {
        let mut device = MemoryDevice::with_frame(arp_request_frame());
        device.transmit_error = Some(io::Error::from(io::ErrorKind::BrokenPipe));
        let mut interface = interface();
        let mut receive_buffer = [0; 128];

        let error = run_once_at(
            &mut device,
            &mut interface,
            &mut receive_buffer,
            Instant::now(),
        )
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert!(device.transmitted_frames.is_empty());
    }

    #[test]
    fn a_too_small_receive_buffer_returns_an_error_without_transmitting() {
        let mut device = MemoryDevice::with_frame(arp_request_frame());
        let mut interface = interface();
        let mut receive_buffer = [0; 8];

        let error = run_once_at(
            &mut device,
            &mut interface,
            &mut receive_buffer,
            Instant::now(),
        )
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(device.transmitted_frames.is_empty());
    }
}
