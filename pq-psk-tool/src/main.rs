use std::fs;
use std::path::PathBuf;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use clap::{Parser, Subcommand};
use ml_kem::{
    kem::{Kem, TryDecapsulate},
    DecapsulationKey768, Encapsulate, EncapsulationKey768, KeyExport, MlKem768, Seed,
};
use rand_core::UnwrapErr;

#[derive(Parser)]
#[command(
    name = "pq-psk-tool",
    about = "ML-KEM-768 key exchange tool for WireGuard PSK-slot post-quantum protection.\n\n\
             Generates a shared 32-byte secret via ML-KEM-768 that can be used as a \
             WireGuard preshared key (PSK) for post-quantum protection."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate an ML-KEM-768 keypair (encapsulation key + decapsulation key).
    /// The encapsulation key is sent to the peer; the decapsulation key is kept secret.
    Keygen {
        /// Output path for the encapsulation key (public, sent to peer)
        #[arg(short = 'e', long, default_value = "mlkem_ek.b64")]
        ek_out: PathBuf,

        /// Output path for the decapsulation key seed (secret, keep local)
        #[arg(short = 'd', long, default_value = "mlkem_dk.b64")]
        dk_out: PathBuf,
    },

    /// Encapsulate: read the peer's encapsulation key, produce a ciphertext and shared secret.
    /// The ciphertext is sent back to the peer; the shared secret is used as the WireGuard PSK.
    Encaps {
        /// Path to the peer's encapsulation key (base64 file)
        ek_file: PathBuf,

        /// Output path for the ciphertext (sent back to peer)
        #[arg(short = 'c', long, default_value = "mlkem_ct.b64")]
        ct_out: PathBuf,

        /// Output path for the PSK (base64-encoded 32-byte shared secret,
        /// directly usable as a WireGuard preshared key)
        #[arg(short = 'p', long, default_value = "psk.b64")]
        psk_out: PathBuf,
    },

    /// Decapsulate: read own decapsulation key and the peer's ciphertext, recover the shared secret.
    /// The shared secret is used as the WireGuard PSK (identical to the encapsulator's).
    Decaps {
        /// Path to own decapsulation key seed (base64 file)
        dk_file: PathBuf,

        /// Path to the ciphertext from the peer (base64 file)
        ct_file: PathBuf,

        /// Output path for the PSK (base64-encoded 32-byte shared secret,
        /// directly usable as a WireGuard preshared key)
        #[arg(short = 'p', long, default_value = "psk.b64")]
        psk_out: PathBuf,
    },
}

fn read_base64_file(path: &PathBuf) -> Vec<u8> {
    let contents = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
    let trimmed = contents.trim();
    BASE64
        .decode(trimmed)
        .unwrap_or_else(|e| panic!("Failed to decode base64 from {}: {}", path.display(), e))
}

fn write_base64_file(path: &PathBuf, data: &[u8]) {
    let encoded = BASE64.encode(data);
    fs::write(path, &encoded)
        .unwrap_or_else(|e| panic!("Failed to write {}: {}", path.display(), e));
    eprintln!("Wrote {} ({} bytes raw) to {}", encoded.len(), data.len(), path.display());
}

fn write_psk_base64(path: &PathBuf, secret: &[u8]) {
    // WireGuard's `wg set ... preshared-key <file>` expects a base64-encoded
    // 32-byte key. Writing the PSK in base64 (not hex) makes the file usable
    // directly, with no conversion step on the operator's side.
    let b64 = BASE64.encode(secret);
    fs::write(path, &b64)
        .unwrap_or_else(|e| panic!("Failed to write {}: {}", path.display(), e));
    eprintln!("Wrote PSK ({} bytes) to {}", secret.len(), path.display());
    eprintln!("Use with: wg set <iface> peer <PUBKEY> preshared-key {}", path.display());
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Keygen { ek_out, dk_out } => {
            let (dk, ek): (DecapsulationKey768, EncapsulationKey768) =
                MlKem768::generate_keypair_from_rng(&mut UnwrapErr(getrandom::SysRng));

            // Serialize encapsulation key (1184 bytes for ML-KEM-768)
            let ek_bytes = ek.to_bytes();
            write_base64_file(&ek_out, ek_bytes.as_slice());

            // Serialize decapsulation key as seed (64 bytes)
            let dk_seed = dk.to_seed().expect("Failed to extract seed from decapsulation key");
            write_base64_file(&dk_out, dk_seed.as_slice());

            eprintln!(
                "\nKeypair generated. Send {} to your peer (it is public).",
                ek_out.display()
            );
            eprintln!("Keep {} secret.", dk_out.display());
        }

        Command::Encaps {
            ek_file,
            ct_out,
            psk_out,
        } => {
            let ek_bytes = read_base64_file(&ek_file);

            let ek = EncapsulationKey768::new(
                ek_bytes.as_slice().try_into().unwrap_or_else(|_| {
                    panic!(
                        "Encapsulation key has wrong size: expected 1184 bytes, got {}",
                        ek_bytes.len()
                    )
                }),
            )
            .expect("Invalid encapsulation key");

            let (ct, shared_secret) = ek.encapsulate_with_rng(&mut UnwrapErr(getrandom::SysRng));

            write_base64_file(&ct_out, ct.as_slice());
            write_psk_base64(&psk_out, shared_secret.as_slice());

            eprintln!(
                "\nEncapsulation complete. Send {} back to the keygen peer.",
                ct_out.display()
            );
        }

        Command::Decaps {
            dk_file,
            ct_file,
            psk_out,
        } => {
            let dk_bytes = read_base64_file(&dk_file);
            let ct_bytes = read_base64_file(&ct_file);

            // Reconstruct decapsulation key from seed
            let seed: Seed = dk_bytes
                .as_slice()
                .try_into()
                .unwrap_or_else(|_| {
                    panic!(
                        "Decapsulation key seed has wrong size: expected 64 bytes, got {}",
                        dk_bytes.len()
                    )
                });
            let dk = DecapsulationKey768::from_seed(seed);

            let ct = ct_bytes.as_slice().try_into().unwrap_or_else(|_| {
                panic!(
                    "Ciphertext has wrong size: expected 1088 bytes, got {}",
                    ct_bytes.len()
                )
            });

            let shared_secret = dk.try_decapsulate(ct)
                .expect("Decapsulation failed");

            write_psk_base64(&psk_out, shared_secret.as_slice());

            eprintln!("\nDecapsulation complete. PSK matches the encapsulator's PSK.");
        }
    }
}
