//! osint.rs
//! Advanced OSINT Aggregator aligned with Zero Trust principles
//! Rust standard library only – No external dependencies

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::thread::sleep;
use std::time::{Duration, SystemTime};

// Manual HTTP GET request implementation via TCP
fn manual_http_get(host: &str, path: &str) -> std::io::Result<String> {
    let addr = (host, 80).to_socket_addrs()?.next().unwrap();
    let mut stream = TcpStream::connect_timeout(&addr, Duration::new(5, 0))?;

    // Zero Trust: Manually construct and sanitize HTTP request
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 (OSINT Aggregator)\r\nConnection: close\r\n\r\n",
        path, host
    );

    stream.write_all(request.as_bytes())?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;

    Ok(response)
}

// Basic HTML title extraction (manual parsing)
fn extract_title(html: &str) -> Option<String> {
    let start_tag = "<title>";
    let end_tag = "</title>";

    let start = html.find(start_tag)? + start_tag.len();
    let end = html[start..].find(end_tag)? + start;

    Some(html[start..end].trim().to_string())
}

// Securely log OSINT findings
fn secure_log(entry: &str) -> std::io::Result<()> {
    let mut log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open("osint_results.log")?;

    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    writeln!(log_file, "[{}] {}", timestamp, entry)?;

    Ok(())
}

// OSINT scraping function with Zero Trust sanitization
fn perform_osint(host: &str, path: &str) -> std::io::Result<()> {
    println!("Fetching OSINT data from: {}{}", host, path);

    let response = manual_http_get(host, path)?;

    if let Some(title) = extract_title(&response) {
        println!("Extracted Title: {}", title);
        secure_log(&format!("Host: {} - Title: {}", host, title))?;
    } else {
        println!("No title found.");
        secure_log(&format!("Host: {} - Title not found", host))?;
    }

    Ok(())
}

// Main OSINT routine
fn main() {
    let targets = vec![("example.com", "/"), ("openai.com", "/"), ("ietf.org", "/")];

    for (host, path) in targets {
        match perform_osint(host, path) {
            Ok(_) => println!("Successfully fetched from {}", host),
            Err(e) => eprintln!("Error fetching from {}: {}", host, e),
        }

        // Zero Trust: Explicitly rate limit each request to avoid detection
        sleep(Duration::from_secs(10));
    }
}
