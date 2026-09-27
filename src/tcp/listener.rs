use std::{collections::HashMap, net::Ipv4Addr};

use super::{TcpFlags, TcpSegment};

pub const DEFAULT_TCP_RECEIVE_WINDOW: u16 = 64_240;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TcpConnectionKey {
    pub local_ip: Ipv4Addr,
    pub local_port: u16,
    pub remote_ip: Ipv4Addr,
    pub remote_port: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpConnectionState {
    SynReceived,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpConnection {
    pub state: TcpConnectionState,
    /// ISS: the first sequence number selected by our stack.
    pub initial_send_sequence: u32,
    /// SND.UNA: the oldest sequence number not yet acknowledged.
    pub send_unacknowledged: u32,
    /// SND.NXT: the next sequence number our stack will send.
    pub send_next: u32,
    /// IRS: the first sequence number received from the peer.
    pub initial_receive_sequence: u32,
    /// RCV.NXT: the next sequence number expected from the peer.
    pub receive_next: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SynAck {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub acknowledgement_number: u32,
    pub window_size: u16,
}

#[derive(Debug)]
pub struct TcpListener {
    local_ip: Ipv4Addr,
    local_port: u16,
    capacity: usize,
    next_initial_sequence: u32,
    connections: HashMap<TcpConnectionKey, TcpConnection>,
}

impl TcpListener {
    pub fn new(
        local_ip: Ipv4Addr,
        local_port: u16,
        capacity: usize,
        initial_sequence: u32,
    ) -> Self {
        Self {
            local_ip,
            local_port,
            capacity,
            next_initial_sequence: initial_sequence,
            connections: HashMap::new(),
        }
    }

    pub fn receive_syn(&mut self, remote_ip: Ipv4Addr, segment: &TcpSegment<'_>) -> Option<SynAck> {
        if !self.accepts_syn(segment) {
            return None;
        }

        let key = TcpConnectionKey {
            local_ip: self.local_ip,
            local_port: self.local_port,
            remote_ip,
            remote_port: segment.source_port,
        };

        if let Some(connection) = self.connections.get(&key) {
            return Some(Self::syn_ack(key, *connection));
        }
        if self.connections.len() >= self.capacity {
            return None;
        }

        let initial_send_sequence = self.next_initial_sequence;
        self.next_initial_sequence = self.next_initial_sequence.wrapping_add(1);
        let connection = TcpConnection {
            state: TcpConnectionState::SynReceived,
            initial_send_sequence,
            send_unacknowledged: initial_send_sequence,
            send_next: initial_send_sequence.wrapping_add(1),
            initial_receive_sequence: segment.sequence_number,
            receive_next: segment.sequence_number.wrapping_add(1),
        };
        self.connections.insert(key, connection);

        Some(Self::syn_ack(key, connection))
    }

    pub fn connection(&self, key: TcpConnectionKey) -> Option<&TcpConnection> {
        self.connections.get(&key)
    }

    pub fn len(&self) -> usize {
        self.connections.len()
    }

    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }

    fn accepts_syn(&self, segment: &TcpSegment<'_>) -> bool {
        segment.destination_port == self.local_port
            && segment.source_port != 0
            && segment.flags.contains(TcpFlags::SYN)
            && !segment.flags.contains(TcpFlags::ACK)
            && !segment.flags.contains(TcpFlags::RST)
            && !segment.flags.contains(TcpFlags::FIN)
            && !segment.flags.contains(TcpFlags::PSH)
            && !segment.flags.contains(TcpFlags::URG)
            && segment.payload.is_empty()
    }

    fn syn_ack(key: TcpConnectionKey, connection: TcpConnection) -> SynAck {
        SynAck {
            source_port: key.local_port,
            destination_port: key.remote_port,
            sequence_number: connection.initial_send_sequence,
            acknowledgement_number: connection.receive_next,
            window_size: DEFAULT_TCP_RECEIVE_WINDOW,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCAL_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
    const REMOTE_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const OTHER_REMOTE_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 3);
    const LOCAL_PORT: u16 = 9000;
    const REMOTE_PORT: u16 = 49_152;
    const INITIAL_SEQUENCE: u32 = 0x1234_5678;
    const REMOTE_SEQUENCE: u32 = 0xaabb_ccdd;

    fn listener(capacity: usize) -> TcpListener {
        TcpListener::new(LOCAL_IP, LOCAL_PORT, capacity, INITIAL_SEQUENCE)
    }

    fn syn() -> TcpSegment<'static> {
        TcpSegment {
            source_port: REMOTE_PORT,
            destination_port: LOCAL_PORT,
            sequence_number: REMOTE_SEQUENCE,
            acknowledgement_number: 0,
            data_offset: 5,
            reserved: 0,
            flags: TcpFlags::SYN,
            window_size: 32_768,
            checksum: 0,
            urgent_pointer: 0,
            options: &[],
            payload: &[],
        }
    }

    fn key(remote_ip: Ipv4Addr, remote_port: u16) -> TcpConnectionKey {
        TcpConnectionKey {
            local_ip: LOCAL_IP,
            local_port: LOCAL_PORT,
            remote_ip,
            remote_port,
        }
    }

    #[test]
    fn accepts_a_syn_and_enters_syn_received() {
        let mut listener = listener(4);

        let reply = listener.receive_syn(REMOTE_IP, &syn()).unwrap();

        assert_eq!(
            reply,
            SynAck {
                source_port: LOCAL_PORT,
                destination_port: REMOTE_PORT,
                sequence_number: INITIAL_SEQUENCE,
                acknowledgement_number: REMOTE_SEQUENCE + 1,
                window_size: DEFAULT_TCP_RECEIVE_WINDOW,
            }
        );
        assert_eq!(
            listener.connection(key(REMOTE_IP, REMOTE_PORT)),
            Some(&TcpConnection {
                state: TcpConnectionState::SynReceived,
                initial_send_sequence: INITIAL_SEQUENCE,
                send_unacknowledged: INITIAL_SEQUENCE,
                send_next: INITIAL_SEQUENCE + 1,
                initial_receive_sequence: REMOTE_SEQUENCE,
                receive_next: REMOTE_SEQUENCE + 1,
            })
        );
    }

    #[test]
    fn syn_consumes_sequence_space_with_wrapping_arithmetic() {
        let mut listener = TcpListener::new(LOCAL_IP, LOCAL_PORT, 1, u32::MAX);
        let mut request = syn();
        request.sequence_number = u32::MAX;

        let reply = listener.receive_syn(REMOTE_IP, &request).unwrap();
        let connection = listener.connection(key(REMOTE_IP, REMOTE_PORT)).unwrap();

        assert_eq!(reply.sequence_number, u32::MAX);
        assert_eq!(reply.acknowledgement_number, 0);
        assert_eq!(connection.send_next, 0);
        assert_eq!(connection.receive_next, 0);
    }

    #[test]
    fn a_duplicate_syn_reuses_the_existing_sequence_numbers() {
        let mut listener = listener(4);

        let first = listener.receive_syn(REMOTE_IP, &syn()).unwrap();
        let second = listener.receive_syn(REMOTE_IP, &syn()).unwrap();

        assert_eq!(second, first);
        assert_eq!(listener.len(), 1);
    }

    #[test]
    fn different_four_tuples_create_independent_connections() {
        let mut listener = listener(4);
        let mut second_syn = syn();
        second_syn.source_port += 1;

        let first = listener.receive_syn(REMOTE_IP, &syn()).unwrap();
        let second = listener.receive_syn(OTHER_REMOTE_IP, &second_syn).unwrap();

        assert_eq!(first.sequence_number, INITIAL_SEQUENCE);
        assert_eq!(second.sequence_number, INITIAL_SEQUENCE + 1);
        assert_eq!(listener.len(), 2);
        assert!(
            listener
                .connection(key(OTHER_REMOTE_IP, REMOTE_PORT + 1))
                .is_some()
        );
    }

    #[test]
    fn a_full_connection_table_ignores_new_connections_but_allows_duplicates() {
        let mut listener = listener(1);
        let first = listener.receive_syn(REMOTE_IP, &syn()).unwrap();
        let mut other = syn();
        other.source_port += 1;

        assert_eq!(listener.receive_syn(OTHER_REMOTE_IP, &other), None);
        assert_eq!(listener.receive_syn(REMOTE_IP, &syn()), Some(first));
        assert_eq!(listener.len(), 1);
    }

    #[test]
    fn a_zero_capacity_listener_never_creates_connections() {
        let mut listener = listener(0);

        assert_eq!(listener.receive_syn(REMOTE_IP, &syn()), None);
        assert!(listener.is_empty());
    }

    #[test]
    fn ignores_segments_that_are_not_supported_initial_syns() {
        let mut listener = listener(16);

        for flags in [
            TcpFlags::ACK,
            TcpFlags::RST,
            TcpFlags::FIN,
            TcpFlags::SYN | TcpFlags::ACK,
            TcpFlags::SYN | TcpFlags::RST,
            TcpFlags::SYN | TcpFlags::FIN,
            TcpFlags::SYN | TcpFlags::PSH,
            TcpFlags::SYN | TcpFlags::URG,
        ] {
            let mut request = syn();
            request.flags = flags;
            assert_eq!(listener.receive_syn(REMOTE_IP, &request), None);
        }

        let mut wrong_port = syn();
        wrong_port.destination_port += 1;
        assert_eq!(listener.receive_syn(REMOTE_IP, &wrong_port), None);

        let mut zero_source_port = syn();
        zero_source_port.source_port = 0;
        assert_eq!(listener.receive_syn(REMOTE_IP, &zero_source_port), None);

        let mut data_bearing_syn = syn();
        data_bearing_syn.payload = b"unsupported TCP Fast Open data";
        assert_eq!(listener.receive_syn(REMOTE_IP, &data_bearing_syn), None);

        assert!(listener.is_empty());
    }

    #[test]
    fn accepts_ecn_flags_and_options_on_a_syn() {
        let mut listener = listener(1);
        let mut request = syn();
        request.flags = TcpFlags::SYN | TcpFlags::ECE | TcpFlags::CWR;
        request.data_offset = 6;
        request.options = &[2, 4, 0x05, 0xb4];

        assert!(listener.receive_syn(REMOTE_IP, &request).is_some());
    }
}
