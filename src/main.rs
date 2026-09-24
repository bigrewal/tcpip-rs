#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    use std::net::Ipv4Addr;

    use anyhow::Context;
    use tcp_ip::{
        MacAddress,
        device::tap::TapDevice,
        interface::NetworkInterface,
        runtime::{RunOutcome, run_with_observer},
    };

    const STACK_MAC: MacAddress = MacAddress::new([0x02, 0, 0, 0, 0, 2]);
    const STACK_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

    let requested_name = std::env::args().nth(1).unwrap_or_else(|| "tap0".to_owned());
    let mut device = TapDevice::open(&requested_name).with_context(|| {
        format!(
            "could not open TAP device {requested_name:?}; ensure /dev/net/tun exists and run with CAP_NET_ADMIN"
        )
    })?;
    let mut interface = NetworkInterface::new(STACK_MAC, STACK_IP);

    eprintln!("listening on {} as {STACK_IP} ({STACK_MAC})", device.name());
    eprintln!("configure the host side in another terminal:");
    eprintln!("  sudo ip address add 10.0.0.1/24 dev {}", device.name());
    eprintln!("  sudo ip link set {} up", device.name());
    eprintln!("  ping {STACK_IP}");
    eprintln!("  printf 'hello UDP\\n' | nc -u -w 1 {STACK_IP} 9000");

    run_with_observer(&mut device, &mut interface, |outcome| match outcome {
        RunOutcome::MalformedFrame { error, .. } => eprintln!("dropped malformed frame: {error}"),
        RunOutcome::ReplyTransmitted {
            received,
            transmitted,
        } => eprintln!("received {received} bytes; transmitted {transmitted} bytes"),
        RunOutcome::Ignored { .. } => {}
    })?;

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("tcp-ip's TAP executable currently requires Linux");
    eprintln!("run it inside a Linux VM to exercise the network stack end to end");
}
