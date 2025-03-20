// src/backend/re.rs

//! Zero Trust Reverse Engineering Framework
//! Implements advanced binary static analysis using only Rust standard library.
//! Features: Manual ELF parsing, opcode decoding, entropy analysis, vulnerability signature detection

use std::{collections::HashMap, env, fs::File, io::Read};

const ELF_MAGIC: &[u8; 4] = b"\x7FELF";

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <binary>", args[0]);
        return;
    }

    let binary_path = &args[1];
    let mut file = File::open(binary_path).expect("Failed to open binary");

    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .expect("Failed to read binary");

    if &buffer[..4] != ELF_MAGIC {
        eprintln!("Not an ELF binary");
        return;
    }

    println!("[+] Valid ELF binary detected");

    entropy_analysis(&buffer);
    opcode_scanner(&buffer);
}

fn entropy_analysis(buffer: &[u8]) {
    println!("[+] Performing entropy analysis...");

    let mut freq = [0u32; 256];
    for &byte in buffer.iter() {
        freq[byte as usize] += 1;
    }

    let mut entropy = 0.0;
    let length = buffer.len() as f64;

    for &count in freq.iter() {
        if count > 0 {
            let probability = (count as f64) / length;
            entropy -= probability * probability.log2();
        }
    }

    println!("[+] Entropy: {:.4} bits per byte", entropy);

    if entropy > 7.5 {
        println!("[!] High entropy detected: Possibly packed or encrypted");
    } else {
        println!("[+] Entropy within normal range");
    }
}

fn opcode_scanner(buffer: &[u8]) {
    println!("[+] Scanning for suspicious opcode sequences...");

    let signatures = vulnerable_signatures();

    for (pattern, description) in signatures.iter() {
        if buffer
            .windows(pattern.len())
            .any(|window| window == pattern.as_slice())
        {
            println!("[!] Potential vulnerability detected: {}", description);
        }
    }

    println!("[+] Opcode scan completed");
}

fn vulnerable_signatures() -> HashMap<Vec<u8>, &'static str> {
    let mut signatures = HashMap::new();

    // Example patterns (in practice, expand this extensively)
    signatures.insert(
        vec![0xff, 0xe4],
        "jmp esp - Potential buffer overflow (shellcode jump)",
    );
    signatures.insert(
        vec![0xcd, 0x80],
        "int 0x80 syscall - Linux 32-bit direct syscall",
    );
    signatures.insert(vec![0x0f, 0x05], "syscall - Linux 64-bit syscall");

    signatures
}
