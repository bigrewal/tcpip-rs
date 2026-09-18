use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    mem,
    os::fd::AsRawFd,
};

use super::EthernetDevice;

const TUN_DEVICE_PATH: &str = "/dev/net/tun";

#[derive(Debug)]
pub struct TapDevice {
    file: File,
    name: String,
}

impl TapDevice {
    pub fn open(requested_name: &str) -> io::Result<Self> {
        validate_name(requested_name)?;

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(TUN_DEVICE_PATH)?;

        // `ifreq` is a C structure shared with the Linux kernel. Starting with
        // zeroes is the required C convention: unused fields and the terminating
        // byte of the interface name must be zero.
        //
        // SAFETY: An all-zero `libc::ifreq` is a valid initial state on Linux.
        let mut request: libc::ifreq = unsafe { mem::zeroed() };
        copy_name_to_request(requested_name, &mut request);

        // `ifr_ifru` is a C union. For TUNSETIFF the kernel interprets this
        // particular member as the interface flags.
        request.ifr_ifru.ifru_flags = (libc::IFF_TAP | libc::IFF_NO_PI) as libc::c_short;

        // SAFETY:
        // - `file` is an open descriptor for `/dev/net/tun`.
        // - `request` points to a live, correctly sized Linux `ifreq`.
        // - TUNSETIFF reads the requested name/flags and writes back the actual name.
        let result = unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF, &mut request) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            file,
            name: name_from_request(&request),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

impl EthernetDevice for TapDevice {
    fn receive(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.file.read(buffer)
    }

    fn transmit(&mut self, frame: &[u8]) -> io::Result<()> {
        // One write corresponds to one TAP frame. A second write would be a
        // second frame, so a partial write is reported rather than retried.
        let written = self.file.write(frame)?;
        if written != frame.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!(
                    "TAP device wrote {written} of {} Ethernet-frame bytes",
                    frame.len()
                ),
            ));
        }

        Ok(())
    }
}

fn validate_name(name: &str) -> io::Result<()> {
    if name.as_bytes().contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TAP device name cannot contain a NUL byte",
        ));
    }
    if name.len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "TAP device name is {} bytes long; maximum is {}",
                name.len(),
                libc::IFNAMSIZ - 1
            ),
        ));
    }

    Ok(())
}

fn copy_name_to_request(name: &str, request: &mut libc::ifreq) {
    for (destination, source) in request.ifr_name.iter_mut().zip(name.bytes()) {
        *destination = source as libc::c_char;
    }
}

fn name_from_request(request: &libc::ifreq) -> String {
    let length = request
        .ifr_name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(request.ifr_name.len());
    let bytes = request.ifr_name[..length]
        .iter()
        .map(|byte| *byte as u8)
        .collect::<Vec<_>>();

    String::from_utf8_lossy(&bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_longest_interface_name() {
        assert!(validate_name("a".repeat(libc::IFNAMSIZ - 1).as_str()).is_ok());
    }

    #[test]
    fn rejects_an_interface_name_that_cannot_fit_with_its_terminator() {
        let error = validate_name("a".repeat(libc::IFNAMSIZ).as_str()).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn copies_and_recovers_an_interface_name() {
        // SAFETY: An all-zero `libc::ifreq` is a valid initial state on Linux.
        let mut request: libc::ifreq = unsafe { mem::zeroed() };

        copy_name_to_request("tap0", &mut request);

        assert_eq!(name_from_request(&request), "tap0");
    }
}
