use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use rusqlite::{params, Connection, Result};
use bip39::{Mnemonic, Language};
use hex::encode;
use ocl::{ProQue, Buffer};

fn main() -> Result<()> {
    let src = include_str!("../../cl/address.cl")
        .to_string()
        + include_str!("../../cl/common.cl")
        + include_str!("../../cl/int_to_address.cl")
        + include_str!("../../cl/just_address.cl")
        + include_str!("../../cl/just_seed.cl")
        + include_str!("../../cl/mnemonic_constants.cl")
        + include_str!("../../cl/ripemd.cl")
        + include_str!("../../cl/secp256k1.cl")
        + include_str!("../../cl/secp256k1_common.cl")
        + include_str!("../../cl/secp256k1_field.cl")
        + include_str!("../../cl/secp256k1_group.cl")
        + include_str!("../../cl/secp256k1_prec.cl")
        + include_str!("../../cl/secp256k1_scalar.cl")
        + include_str!("../../cl/sha2.cl")
        + include_str!("../../cl/keccak.cl")
        + include_str!("../../cl/pbkdf2.cl")
        + include_str!("../../cl/Mersenne_Twister.cl")
        + include_str!("../../cl/BIP32.cl");

    let pro_que = ProQue::builder().src(src).build().unwrap();

    let path = Path::new("basa.bin");
    let mut file = File::open(&path)?;
    let mut seeds = Vec::new();
    file.read_to_end(&mut seeds)?;

    let conn = Connection::open("basaadres.db")?;

    for chunk in seeds.chunks(4) {
        if chunk.len() == 4 {
            let entropy_seed: u32 = u32::from_le_bytes(chunk.try_into().unwrap());
            let entropy_buffer = generate_entropy(&pro_que, entropy_seed);

            let mnemonic = Mnemonic::from_entropy(&entropy_buffer, Language::English).unwrap();
            let phrase = mnemonic.phrase();

            let eth_address = generate_eth_address(&pro_que, phrase);

            let seed_hex = encode(chunk);
            conn.execute(
                "INSERT INTO addresses (rng_seed, eth_address) VALUES (?1, ?2)",
                params![seed_hex, eth_address],
            )?;
        }
    }

    Ok(())
}

fn generate_entropy(pro_que: &ProQue, seed: u32) -> Vec<u8> {
    let mt_buffer = Buffer::<u32>::builder()
        .queue(pro_que.queue().clone())
        .len(624)
        .build().unwrap();

    let entropy_buffer = Buffer::<u32>::builder()
        .queue(pro_que.queue().clone())
        .len(16)
        .build().unwrap();

    let kernel = pro_que.kernel_builder("mersenne_twister")
        .arg(&mt_buffer)
        .arg(&entropy_buffer)
        .arg(seed)
        .build().unwrap();

    unsafe {
        kernel.enq().unwrap();
    }

    let mut entropy_vec = vec![0u32; 16];
    entropy_buffer.read(&mut entropy_vec).enq().unwrap();

    let mut result = Vec::new();
    for &val in entropy_vec.iter() {
        result.extend_from_slice(&val.to_le_bytes());
    }

    result
}

fn generate_eth_address(pro_que: &ProQue, phrase: &str) -> String {
    let phrase_bytes = phrase.as_bytes();
    let salt = b"mnemonic";

    let password_buffer = Buffer::<u8>::builder()
        .queue(pro_que.queue().clone())
        .len(phrase_bytes.len())
        .copy_host_slice(phrase_bytes)
        .build().unwrap();

    let salt_buffer = Buffer::<u8>::builder()
        .queue(pro_que.queue().clone())
        .len(salt.len())
        .copy_host_slice(salt)
        .build().unwrap();

    let result_buffer = Buffer::<u8>::builder()
        .queue(pro_que.queue().clone())
        .len(64)
        .build().unwrap();

    let kernel = pro_que.kernel_builder("pbkdf2_hmac_sha512")
        .arg(&password_buffer)
        .arg(&salt_buffer)
        .arg(2048u32)
        .arg(&result_buffer)
        .build().unwrap();

    unsafe {
        kernel.enq().unwrap();
    }

    let mut result_vec = vec![0u8; 64];
    result_buffer.read(&mut result_vec).enq().unwrap();

    let eth_address = derive_eth_address(&pro_que, &result_vec);

    eth_address
}

fn derive_eth_address(pro_que: &ProQue, seed: &[u8]) -> String {
    let master_priv_buffer = Buffer::<u8>::builder()
        .queue(pro_que.queue().clone())
        .len(32)
        .build().unwrap();

    let chain_code_buffer = Buffer::<u8>::builder()
        .queue(pro_que.queue().clone())
        .len(32)
        .build().unwrap();

    let seed_buffer = Buffer::<u8>::builder()
        .queue(pro_que.queue().clone())
        .len(seed.len())
        .copy_host_slice(seed)
        .build().unwrap();

    let kernel = pro_que.kernel_builder("new_master_from_seed")
        .arg(&seed_buffer)
        .arg(&master_priv_buffer)
        .arg(&chain_code_buffer)
        .build().unwrap();

    unsafe {
        kernel.enq().unwrap();
    }

    // Generate the child key for m/44'/60'/0'/0/0
    let child_priv_buffer = Buffer::<u8>::builder()
        .queue(pro_que.queue().clone())
        .len(32)
        .build().unwrap();

    let child_chain_buffer = Buffer::<u8>::builder()
        .queue(pro_que.queue().clone())
        .len(32)
        .build().unwrap();

    let kernel = pro_que.kernel_builder("derive_child_key")
        .arg(&master_priv_buffer)
        .arg(&chain_code_buffer)
        .arg(0u32)  // Assuming 0 for demonstration
        .arg(&child_priv_buffer)
        .arg(&child_chain_buffer)
        .build().unwrap();

    unsafe {
        kernel.enq().unwrap();
    }

    let pub_key_buffer = Buffer::<u8>::builder()
        .queue(pro_que.queue().clone())
        .len(33)
        .build().unwrap();

    let kernel = pro_que.kernel_builder("public_from_private")
        .arg(&child_priv_buffer)
        .arg(&pub_key_buffer)
        .build().unwrap();

    unsafe {
        kernel.enq().unwrap();
    }

    let eth_address_buffer = Buffer::<u8>::builder()
        .queue(pro_que.queue().clone())
        .len(20)
        .build().unwrap();

    let kernel = pro_que.kernel_builder("generate_eth_address")
        .arg(&pub_key_buffer)
        .arg(&eth_address_buffer)
        .build().unwrap();

    unsafe {
        kernel.enq().unwrap();
    }

    let mut eth_address_vec = vec![0u8; 20];
    eth_address_buffer.read(&mut eth_address_vec).enq().unwrap();

    hex::encode(eth_address_vec)
}
