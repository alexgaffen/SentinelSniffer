use pyo3::prelude::*;
use pnet::datalink::{self};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;

/// Diagnostic tool to see what hardware Rust can actually see
#[pyfunction]
fn get_interfaces() -> PyResult<Vec<String>> {
    let mut result = Vec::new();
    for iface in datalink::interfaces() {
        let info = format!("Name: {} | IPs: {:?} | Up: {} | Loopback: {}",
            iface.name, iface.ips, iface.is_up(), iface.is_loopback());
        result.push(info);
    }
    Ok(result)
}

#[pyfunction]
fn sniff_packets(count: usize) -> PyResult<Vec<(String, String, String, usize)>> {
    let mut results = Vec::new();
    let interfaces = datalink::interfaces();

    // RELAXED FILTER: We removed the `is_up()` check because Windows lies.
    // If it has an IP address and isn't the loopback (localhost), we use it.
    let interface = interfaces.into_iter()
        .filter(|iface| !iface.is_loopback() && !iface.ips.is_empty())
        .next()
        .expect("Error: No active network interfaces found even with relaxed filter!");

    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Failed to open channel: {}", e)
    };

    let mut captured = 0;
    while captured < count {
        match rx.next() {
            Ok(packet_bytes) => {
                if let Some(ethernet) = EthernetPacket::new(packet_bytes) {
                    if ethernet.get_ethertype() == EtherTypes::Ipv4 {
                        if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                            let src_ip = ipv4.get_source().to_string();
                            let dst_ip = ipv4.get_destination().to_string();
                            let size = packet_bytes.len();
                            let protocol = match ipv4.get_next_level_protocol() {
                                pnet::packet::ip::IpNextHeaderProtocols::Tcp => "TCP",
                                pnet::packet::ip::IpNextHeaderProtocols::Udp => "UDP",
                                _ => "Other",
                            };
                            results.push((protocol.to_string(), src_ip, dst_ip, size));
                            captured += 1;
                        }
                    }
                }
            },
            Err(_) => continue,
        }
    }
    Ok(results)
}

#[pymodule]
fn sentinel_sniffer(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(sniff_packets, m)?)?;
    m.add_function(wrap_pyfunction!(get_interfaces, m)?)?; // Expose our new tool
    Ok(())
}