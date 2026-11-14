use ff3::Ff3;
use std::{hint::black_box, time::Instant};

fn run_case(label: &str, alphabet: &str, tweak: &[u8], len: usize, iterations: usize) {
    let cipher = Ff3::new(&[0x42; 16], alphabet).unwrap();
    let input = alphabet.chars().next().unwrap().to_string().repeat(len);

    // Warm up the AES schedule and code paths.
    for _ in 0..2_000 {
        black_box(cipher.encrypt(tweak, black_box(&input)).unwrap());
    }

    let start = Instant::now();
    for _ in 0..iterations {
        black_box(cipher.encrypt(tweak, black_box(&input)).unwrap());
    }
    let allocated_elapsed = start.elapsed();
    let mut output = String::with_capacity(input.len());
    for _ in 0..2_000 {
        cipher
            .encrypt_into(tweak, black_box(&input), black_box(&mut output))
            .unwrap();
    }
    let start = Instant::now();
    for _ in 0..iterations {
        cipher
            .encrypt_into(tweak, black_box(&input), black_box(&mut output))
            .unwrap();
    }
    let reused_elapsed = start.elapsed();
    let ops_per_sec = iterations as f64 / allocated_elapsed.as_secs_f64();
    let reused_ops_per_sec = iterations as f64 / reused_elapsed.as_secs_f64();
    println!(
        "{label:22} {len:2} symbols: alloc {ops_per_sec:10.0}/s ({:.1} ns); reused {reused_ops_per_sec:10.0}/s ({:.1} ns)",
        allocated_elapsed.as_nanos() as f64 / iterations as f64,
        reused_elapsed.as_nanos() as f64 / iterations as f64,
    );
}

fn main() {
    let decimal = "0123456789";
    let base26 = "abcdefghijklmnopqrstuvwxyz";
    let base64 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";
    let tweak = [0u8; 7];

    println!("FF3-1 throughput; AES-128; release build; allocated vs reused output");
    run_case("decimal", decimal, &tweak, 10, 100_000);
    run_case("decimal", decimal, &tweak, 36, 100_000);
    run_case("decimal max length", decimal, &tweak, 56, 100_000);
    run_case("base 26", base26, &tweak, 32, 100_000);
    run_case("base 64", base64, &tweak, 20, 100_000);
}
