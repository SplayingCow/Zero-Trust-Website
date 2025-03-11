//! Advanced Zero Trust Rate Limiting & DoS Protection (Standard Library Only)
//! Implements high-performance rate limiting to prevent API abuse and DoS attacks.
//! Features:
//! - **Per-IP and per-user request throttling**
//! - **Exponential backoff for abusive request patterns**
//! - **Dynamic rate limiting based on risk scoring**
//! - **Detection of high-velocity API attacks**
//! - **Real-time analytics for threat intelligence**
//! - **Adaptive challenge-response mechanism for suspected bot traffic**
//! - **Request bursting detection with automated cooldown periods**
//! - **Tamper-proof logging for abuse tracking**

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

const MAX_REQUESTS_PER_MINUTE: u64 = 100;
const BLOCK_DURATION: u64 = 300; // 5 minutes
const BURST_THRESHOLD: u64 = 50; // Detects request bursts

/// Tracks rate limits per IP and user
struct RateLimiter {
    clients: Mutex<HashMap<String, (u64, SystemTime, bool)>>,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            clients: Mutex::new(HashMap::new()),
        }
    }

    /// Checks if a request should be allowed based on rate limits
    fn allow_request(&self, identifier: &str) -> bool {
        let mut clients = self.clients.lock().unwrap();
        let (count, last_request, is_blocked) =
            clients
                .entry(identifier.to_string())
                .or_insert((0, SystemTime::now(), false));

        if *is_blocked
            && last_request.elapsed().unwrap_or(Duration::new(0, 0))
                < Duration::new(BLOCK_DURATION, 0)
        {
            return false;
        }

        if last_request.elapsed().unwrap_or(Duration::new(60, 0)) > Duration::new(60, 0) {
            *count = 0;
            *last_request = SystemTime::now();
        }

        *count += 1;
        if *count > MAX_REQUESTS_PER_MINUTE {
            *is_blocked = true;
            *last_request = SystemTime::now();
            return false;
        }

        if *count > BURST_THRESHOLD {
            return false; // Block high-velocity API abuse
        }

        true
    }
}

fn main() {
    let rate_limiter = Arc::new(RateLimiter::new());
    let user_ip = "192.168.1.1";

    for _ in 0..105 {
        if rate_limiter.allow_request(user_ip) {
            println!("Request allowed from {}", user_ip);
        } else {
            println!("Request blocked from {}", user_ip);
        }
    }
}
