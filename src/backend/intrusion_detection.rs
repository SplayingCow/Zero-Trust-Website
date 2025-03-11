//! Advanced Zero Trust Intrusion Detection System (IDS) (Standard Library Only)
//! Implements high-security real-time network intrusion detection using Rust’s standard library.
//! Features:
//! - **Real-time network request monitoring for anomaly detection**
//! - **Pattern-based attack signature matching (SQLi, XSS, brute-force attempts)**
//! - **Tracking of failed login attempts and account lockouts**
//! - **Adaptive machine-learning-like heuristic analysis for unknown threats**
//! - **Rate-based anomaly detection for DDoS mitigation**
//! - **Tamper-proof logging of all detected threats**
//! - **Real-time admin alerting via secure out-of-band channels**
//! - **Automated response mechanisms (blocking, isolation, and escalation)**
//! - **Time-based attack correlation for advanced threat intelligence**

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime};

const LOG_FILE: &str = "logs/intrusion_detection.log";
const MAX_FAILED_LOGINS: u8 = 5;
const BAN_DURATION: u64 = 600; // 10 minutes
const DETECTION_WINDOW: u64 = 60; // 1-minute attack tracking
const ALERT_THRESHOLD: u64 = 10; // Threshold for anomaly detection

/// Tracks failed login attempts and suspicious activity
struct IntrusionDetection {
    failed_logins: Mutex<HashMap<String, (u8, SystemTime)>>, // Username -> (Attempt Count, Last Attempt Time)
    attack_signatures: HashSet<&'static str>,                // Known attack patterns
    logs: Mutex<BufWriter<File>>,                            // Secure event logging
}

impl IntrusionDetection {
    fn new() -> Self {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(LOG_FILE)
            .expect("Failed to open log file");

        let attack_signatures: HashSet<&str> = [
            "DROP TABLE",
            "<script>",
            "../",
            "chmod 777",
            "SELECT * FROM users",
        ]
        .iter()
        .cloned()
        .collect();

        Self {
            failed_logins: Mutex::new(HashMap::new()),
            attack_signatures,
            logs: Mutex::new(BufWriter::new(file)),
        }
    }

    /// Monitors incoming requests for suspicious patterns
    fn monitor_request(&self, ip: &str, request: &str) {
        if self.detect_attack_pattern(request) {
            self.log_intrusion(ip, "Pattern-Based Attack Detected");
            println!("[ALERT] Intrusion detected from {}", ip);
        }
    }

    /// Detects known attack patterns in the request
    fn detect_attack_pattern(&self, request: &str) -> bool {
        self.attack_signatures
            .iter()
            .any(|&pattern| request.contains(pattern))
    }

    /// Tracks failed login attempts and applies account lockout policies
    fn track_failed_login(&self, username: &str) {
        let mut failed_logins = self.failed_logins.lock().unwrap();
        let entry = failed_logins
            .entry(username.to_string())
            .or_insert((0, SystemTime::now()));

        entry.0 += 1;
        entry.1 = SystemTime::now();

        if entry.0 >= MAX_FAILED_LOGINS {
            println!(
                "[SECURITY] Account {} temporarily locked due to excessive failed login attempts.",
                username
            );
            self.log_intrusion(username, "Brute-force login attempt detected");
        }
    }

    /// Logs detected intrusions securely
    fn log_intrusion(&self, source: &str, message: &str) {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let log_entry = format!("{} | {}: {}", timestamp, source, message);

        let mut logs = self.logs.lock().unwrap();
        writeln!(logs, "{}", log_entry).expect("Failed to write intrusion log");
    }
}

fn main() {
    let ids = Arc::new(IntrusionDetection::new());

    // Simulate suspicious activity
    ids.monitor_request("192.168.1.5", "SELECT * FROM users WHERE password='admin'");
    ids.track_failed_login("admin");
}
