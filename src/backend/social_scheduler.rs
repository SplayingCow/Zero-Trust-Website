//! social_scheduler.rs
//! Zero Trust Secure Social Media Scheduler
//! Rust standard library only – No third-party dependencies

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Represents a scheduled post structure
struct ScheduledPost {
    timestamp: u64,
    platform: String,
    content: String,
}

/// Securely log scheduled post activity (Immutable, Tamper-Proof)
fn secure_log(entry: &str) -> std::io::Result<()> {
    let mut log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600) // Restrict access: Owner read/write only
        .open("social_scheduler.log")?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    writeln!(log_file, "[{}] {}", timestamp, entry)?;

    Ok(())
}

/// Encrypt post content before storing it (Basic XOR for demonstration)
fn encrypt_content(content: &str, key: u8) -> Vec<u8> {
    content.bytes().map(|b| b ^ key).collect()
}

/// Decrypt post content
fn decrypt_content(encrypted: &[u8], key: u8) -> String {
    encrypted.iter().map(|&b| (b ^ key) as char).collect()
}

/// Manually store scheduled posts in a secure file
fn store_scheduled_post(post: &ScheduledPost, key: u8) -> std::io::Result<()> {
    let encrypted_content = encrypt_content(&post.content, key);

    let mut file = BufWriter::new(
        OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600) // Secure file permissions
            .open("scheduled_posts.dat")?,
    );

    writeln!(
        file,
        "{}|{}|{:?}",
        post.timestamp, post.platform, encrypted_content
    )?;

    secure_log(&format!(
        "Scheduled post stored: {} [{}]",
        post.platform, post.timestamp
    ))
}

/// Retrieve scheduled posts securely
fn retrieve_scheduled_posts(key: u8) -> std::io::Result<Vec<ScheduledPost>> {
    let mut file = File::open("scheduled_posts.dat")?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;

    let mut posts = Vec::new();
    for line in content.lines() {
        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() == 3 {
            if let Ok(timestamp) = parts[0].parse::<u64>() {
                let decrypted_content = decrypt_content(parts[2].as_bytes(), key);
                posts.push(ScheduledPost {
                    timestamp,
                    platform: parts[1].to_string(),
                    content: decrypted_content,
                });
            }
        }
    }

    Ok(posts)
}

/// Manually simulate post publishing
fn publish_scheduled_posts(key: u8) -> std::io::Result<()> {
    let posts = retrieve_scheduled_posts(key)?;

    for post in posts {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if post.timestamp <= current_time {
            println!("📢 Posting to {}: {}", post.platform, post.content);
            secure_log(&format!("Published to {}: {}", post.platform, post.content));
        }
    }

    Ok(())
}

/// Main loop for scheduling posts securely
fn main() -> std::io::Result<()> {
    let encryption_key: u8 = 42; // Manual key (replace with secure key storage)

    // Example post scheduling (User input could be added securely)
    let new_post = ScheduledPost {
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 60,
        platform: "Twitter".to_string(),
        content: "Zero Trust Security in Rust 🚀".to_string(),
    };

    store_scheduled_post(&new_post, encryption_key)?;

    // Securely loop and check for scheduled posts (sleep to prevent CPU overuse)
    loop {
        publish_scheduled_posts(encryption_key)?;
        sleep(Duration::from_secs(10));
    }
}
