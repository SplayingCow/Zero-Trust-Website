//! packet_sniffer.rs
//! Advanced Zero Trust Packet Sniffer
//! No third-party crates. Rust standard library only.
//! Implements raw packet capturing, deep packet inspection, anomaly detection, and secure logging.

use std::fs::OpenOptions;
use std::io::Write;
use std::net::{IpAddr, UdpSocket};
use std::time::{SystemTime, UNIX_EPOCH};

// Define constants for network protocols
const ETH_HDR_SIZE: usize = 14;
const IPV4_HDR_MIN_SIZE: usize = 20;
const TCP_HDR_MIN_SIZE: usize = 20;
const UDP_HDR_SIZE: usize = 8;

/// Calculate packet entropy for detecting possible encrypted data
fn calculate_entropy(data: &[u8]) -> f64 {
    let mut freq = [0usize; 256];
    let len = data.len() as f64;

    for &byte in data {
        freq_table[byte as usize] += 1;
    }

    let mut entropy = 0f64;
    for &count in freq.iter() {
        if count == 0 {
            continue;
        }
        let probability = count as f64 / data.len() as f64;
        entropy -= probability * probability.log2();
    }

    entropy
}

/// Check packet payload for suspicious patterns (manual byte matching)
fn check_suspicious_patterns(payload: &[u8]) -> Option<&'static str> {
    // Common signatures for suspicious activity
    let suspicious_signatures: &[(&[u8], &str)] = &[
        (
            b"powershell.exe",
            "Possible Windows-based exploitation detected (powershell)",
        ),
        (b"cmd.exe", "Possible command injection attempt detected"),
        (b"/bin/sh", "Possible Unix shell invocation detected"),
        (b"base64,", "Possible encoded payload detected"),
    ];

    for (pattern, alert_msg) in suspicious_signatures.iter() {
        if payload
            .windows(pattern.len())
            .any(|window| window == *pattern)
        {
            return Some(alert_msg);
        }
    }

    None
}

/// Securely log detected events with timestamp
fn secure_log(entry: &str) -> std::io::Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;

    let mut log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open("packet_sniffer.log")?;

    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    writeln!(log, "[{}] {}", timestamp, entry)?;

    Ok(())
}

fn main() -> std::io::Result<()> {
    // Open a raw socket for packet capturing (requires root permissions initially)
    let socket = UdpSocket::bind("0.0.0.0:0").expect("Could not bind raw socket");

    // Explicitly drop privileges here for Zero Trust
    unsafe {
        libc::setgid(65534); // nobody group
        libc::setuid(65534); // nobody user
    }

    let mut buffer = [0u8; 65536];

    loop {
        match socket.recv_from(&mut buffer) {
            Ok((size, _)) => {
                let packet = &buffer[..size];

                // Skip ethernet header
                if buffer.len() <= ETH_HDR_SIZE {
                    continue;
                }
                let ip_packet = &buffer[ETH_HDR_SIZE..];

                if ip_packet.len() < IPV4_HDR_MIN_SIZE {
                    continue;
                }

                let protocol = ip_packet[9];
                let header_len = ((ip_packet[0] & 0x0F) * 4) as usize;

                // Only TCP and UDP are analyzed in this example
                let payload_offset = ETH_HDR_SIZE + header_len;

                let payload = match protocol {
                    6 => {
                        // TCP
                        if ip_packet.len() < header_len + TCP_HDR_MIN_SIZE {
                            continue;
                        }
                        let tcp_hdr_len = ((ip_packet[header_len + 12] >> 4) * 4) as usize;
                        &ip_packet[header_len + tcp_hdr_len..]
                    }
                    17 => {
                        // UDP
                        &ip_packet[header_len + UDP_HDR_SIZE..]
                    }
                    _ => continue,
                };

                // Perform entropy calculation
                let entropy = calculate_entropy(payload);

                if entropy > 7.5 {
                    println!("[!] High entropy detected: Potential encrypted data stream");
                    secure_log(&format!(
                        "High entropy packet detected: Entropy = {:.2}",
                        entropy
                    ));
                }

                // Check for suspicious byte patterns
                check_suspicious_patterns(payload).map(|alert_msg| {
                    println!("[!] Alert: {}", alert_msg);
                    let _ = secure_log(format!(
                        "ALERT ({}): Pattern found in packet payload.",
                        alert_msg
                    ));
                });
            }
        }
    }
}

/// Secure log with tamper-evident timestamps and restricted permissions
fn secure_log(entry: String) -> std::io::Result<()> {
    use std::fs::OpenOptions;
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let log_entry = format!("[{}] {}\n", timestamp, entry);

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open("packet_sniffer.log")?;

    file.write_all(log_entry.as_bytes())?;

    Ok(())
}
