use std::io;

#[cfg(target_os = "linux")]
pub mod tap;

/// A source and sink of complete Ethernet frames, excluding the frame check sequence.
pub trait EthernetDevice {
    fn receive(&mut self, buffer: &mut [u8]) -> io::Result<usize>;

    fn transmit(&mut self, frame: &[u8]) -> io::Result<()>;
}
