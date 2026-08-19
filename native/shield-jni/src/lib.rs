//! JNI bridge: exposes Sapling shield functionality (key/address derivation
//! and shield block sync) from the Rust `pivx-wallet-kit` to
//! `dev.jpivx.wallet.crypto.ShieldKeys` on the Java side.
//!
//! Derivation mirrors `wallet::create_wallet_from_mnemonic` and `keys::*`:
//! - take the first 32 bytes of the 64-byte BIP39 seed,
//! - `spending_key_from_seed(seed32, 0)` (ZIP32 path `m/32'/119'/0'`),
//! - extfvk → bech32, default diversified payment address → `ps1...`,
//! - `shield_address_at` scans for the next valid diversifier from a start index,
//! - `handle_blocks` trial-decrypts outputs, surfaces spent nullifiers, and
//!   advances the commitment tree + note witnesses.
//!
//! Every export wraps its body in `catch_unwind`: a Rust panic must never
//! unwind across the JNI boundary (undefined behaviour). Errors surface as
//! thrown `java/lang/IllegalArgumentException`s. Returning a null pointer is
//! the JNI-correct way to propagate a pending exception back to the JVM.

use std::error::Error;
use std::panic::{catch_unwind, AssertUnwindSafe};

use jni::objects::{JClass, JObject, JObjectArray, JString};
use jni::sys::{jbyteArray, jlong, jobjectArray, jstring};
use jni::JNIEnv;

use pivx_wallet_kit::keys;
use pivx_wallet_kit::sapling::builder::{create_shield_transaction, select_shield_notes};
use pivx_wallet_kit::sapling::prover::verify_and_load_params;
use pivx_wallet_kit::sapling::sync::{handle_blocks, ShieldBlock};
use pivx_wallet_kit::wallet::{SerializedNote, WalletData};

/// Run `f` with the JNIEnv, converting any error/panic into a thrown Java
/// exception and `None`. `AssertUnwindSafe` is fine: the env borrow never
/// outlives the call and a caught panic returns immediately.
fn guard<T, F>(env: &mut JNIEnv, f: F) -> Option<T>
where
    F: FnOnce(&mut JNIEnv) -> Result<T, Box<dyn Error>>,
{
    match catch_unwind(AssertUnwindSafe(|| f(env))) {
        Ok(Ok(value)) => Some(value),
        Ok(Err(e)) => {
            let _ = env.throw_new("java/lang/IllegalArgumentException", e.to_string());
            None
        }
        Err(_) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                "internal panic in jpivx-shield-jni",
            );
            None
        }
    }
}

/// Extract the 64-byte BIP39 seed from a Java byte array and take its first
/// 32 bytes — exactly what `create_wallet_from_mnemonic` feeds into
/// `spending_key_from_seed`.
fn seed32_from_jbyte_array(
    env: &mut JNIEnv,
    bip39_seed: jbyteArray,
) -> Result<[u8; 32], Box<dyn Error>> {
    // from_raw only wraps the incoming pointer (no dereference), so passing
    // the JVM-owned array pointer here is safe; we never drop it as owned.
    let bytes =
        env.convert_byte_array(unsafe { jni::objects::JByteArray::from_raw(bip39_seed) })?;
    if bytes.len() < 32 {
        return Err(format!(
            "BIP39 seed must be at least 32 bytes, got {}",
            bytes.len()
        )
        .into());
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes[..32]);
    Ok(seed)
}

/// JSON wire shape for one block of shield data coming from Java.
/// `txs` are hex-encoded raw/compact tx packets (0x03/0x04 prefixed),
/// exactly as parsed from the `/getshielddata` binary stream.
#[derive(serde::Deserialize)]
struct JniShieldBlock {
    height: u32,
    txs: Vec<String>,
}

impl TryFrom<JniShieldBlock> for ShieldBlock {
    type Error = Box<dyn Error>;

    fn try_from(b: JniShieldBlock) -> Result<Self, Self::Error> {
        let mut txs = Vec::with_capacity(b.txs.len());
        for hex in &b.txs {
            if hex.len() % 2 != 0 {
                return Err(format!("odd-length hex tx in block {}: {}", b.height, hex).into());
            }
            txs.push(pivx_wallet_kit::simd::hex::hex_string_to_bytes(hex));
        }
        Ok(ShieldBlock { height: b.height, txs })
    }
}

/// Derive the bech32-encoded extended full viewing key from a 64-byte BIP39 seed.
///
/// Java signature: `static native String nativeExtfvk(byte[] bip39Seed)`
#[no_mangle]
pub extern "system" fn Java_dev_jpivx_wallet_crypto_ShieldKeys_nativeExtfvk(
    mut env: JNIEnv,
    _class: JClass,
    bip39_seed: jbyteArray,
) -> jstring {
    guard(&mut env, |env| {
        let seed = seed32_from_jbyte_array(env, bip39_seed)?;
        let extsk = keys::spending_key_from_seed(&seed, 0)?;
        let extfvk = keys::full_viewing_key(&extsk);
        let encoded = keys::encode_extfvk(&extfvk);
        let jstr = env.new_string(encoded)?;
        Ok(jstr.into_raw())
    })
    .unwrap_or(std::ptr::null_mut())
}

/// Derive the default diversified shield payment address (`ps1...`) from a
/// 64-byte BIP39 seed.
///
/// Java signature: `static native String nativeDefaultShieldAddress(byte[] bip39Seed)`
#[no_mangle]
pub extern "system" fn Java_dev_jpivx_wallet_crypto_ShieldKeys_nativeDefaultShieldAddress(
    mut env: JNIEnv,
    _class: JClass,
    bip39_seed: jbyteArray,
) -> jstring {
    guard(&mut env, |env| {
        let seed = seed32_from_jbyte_array(env, bip39_seed)?;
        let extsk = keys::spending_key_from_seed(&seed, 0)?;
        let extfvk = keys::full_viewing_key(&extsk);
        let encoded = keys::encode_extfvk(&extfvk);
        let address = keys::get_default_address(&encoded)?;
        let jstr = env.new_string(address)?;
        Ok(jstr.into_raw())
    })
    .unwrap_or(std::ptr::null_mut())
}

/// Derive the shield payment address at (or after) the given diversifier
/// start index. Not every index yields a valid diversifier (~50% rejection),
/// so the kit scans forward; the index actually used is returned alongside.
///
/// Returns a `String[2]`: `{ usedIndex, address }`.
///
/// Java signature: `static native String[] nativeShieldAddressAt(String extfvk, long startIndex)`
#[no_mangle]
pub extern "system" fn Java_dev_jpivx_wallet_crypto_ShieldKeys_nativeShieldAddressAt(
    mut env: JNIEnv,
    _class: JClass,
    extfvk: JString,
    start_index: jlong,
) -> jobjectArray {
    guard(&mut env, |env| {
        let encoded: String = env.get_string(&extfvk)?.into();
        if !(0..=u32::MAX as i64).contains(&start_index) {
            return Err(format!("start_index out of u32 range: {start_index}").into());
        }
        let (used, address) = keys::shield_address_at(&encoded, start_index as u32)?;

        let string_class = env.find_class("java/lang/String")?;
        let array: JObjectArray = env.new_object_array(2, string_class, JObject::null())?;
        let idx_jstr = env.new_string(used.to_string())?;
        let addr_jstr = env.new_string(address)?;
        env.set_object_array_element(&array, 0, idx_jstr)?;
        env.set_object_array_element(&array, 1, addr_jstr)?;
        Ok(array.into_raw())
    })
    .unwrap_or(std::ptr::null_mut())
}

/// Process one batch of shield blocks: decrypt notes, extract nullifiers,
/// advance the commitment tree and every existing note's witness.
///
/// Inputs:
/// - `tree_hex`   — hex-encoded commitment tree (from wallet state),
/// - `blocks_json` — `[{"height": H, "txs": ["<hex>", ...]}, ...]`,
/// - `extfvk`     — bech32 extended full viewing key,
/// - `notes_json` — JSON array of the kit's `SerializedNote` shape.
///
/// Returns the kit's `HandleBlocksResult` as JSON —
/// `{commitment_tree, new_notes, updated_notes, nullifiers}`.
///
/// Java signature:
/// `static native String nativeHandleBlocks(String treeHex, String blocksJson, String extfvk, String notesJson)`
#[no_mangle]
pub extern "system" fn Java_dev_jpivx_wallet_crypto_ShieldKeys_nativeHandleBlocks(
    mut env: JNIEnv,
    _class: JClass,
    tree_hex: JString,
    blocks_json: JString,
    extfvk: JString,
    notes_json: JString,
) -> jstring {
    guard(&mut env, |env| {
        let tree_hex: String = env.get_string(&tree_hex)?.into();
        let blocks_json: String = env.get_string(&blocks_json)?.into();
        let extfvk: String = env.get_string(&extfvk)?.into();
        let notes_json: String = env.get_string(&notes_json)?.into();

        let jni_blocks: Vec<JniShieldBlock> = serde_json::from_str(&blocks_json)?;
        let blocks: Vec<ShieldBlock> = jni_blocks
            .into_iter()
            .map(ShieldBlock::try_from)
            .collect::<Result<_, _>>()?;

        let notes: Vec<SerializedNote> = serde_json::from_str(&notes_json)?;

        let result = handle_blocks(&tree_hex, blocks, &extfvk, notes)?;
        let out = serde_json::to_string(&result)?;
        let jstr = env.new_string(out)?;
        Ok(jstr.into_raw())
    })
    .unwrap_or(std::ptr::null_mut())
}

/// Build and sign a shield transaction spending the wallet's notes.
///
/// Inputs:
/// - `wallet_json` — the full kit-shaped `WalletData` JSON (plaintext in-memory
///   copy; jpivx's Jackson shape is field-compatible, extra fields ignored),
/// - `to_address` — `ps1...` (shield) or `D...` (transparent) destination,
/// - `amount_sat` — amount in satoshi (i64; must fit u64),
/// - `memo` — optional memo text ("" for none; shield destinations only),
/// - `block_height` — chain tip + 1,
/// - `spend_params_path` / `output_params_path` — files holding the Sapling
///   Groth16 parameters (SHA256-verified against the kit's pins).
///
/// Returns the kit's `TransactionResult` as JSON — `{txhex, nullifiers, amount, fee}`.
///
/// Java signature:
/// `static native String nativeCreateShieldTransaction(String walletJson, String toAddress, long amountSat, String memo, long blockHeight, String spendParamsPath, String outputParamsPath)`
#[no_mangle]
pub extern "system" fn Java_dev_jpivx_wallet_crypto_ShieldKeys_nativeCreateShieldTransaction(
    mut env: JNIEnv,
    _class: JClass,
    wallet_json: JString,
    to_address: JString,
    amount_sat: jlong,
    memo: JString,
    block_height: jlong,
    spend_params_path: JString,
    output_params_path: JString,
) -> jstring {
    guard(&mut env, |env| {
        let wallet_json: String = env.get_string(&wallet_json)?.into();
        let to_address: String = env.get_string(&to_address)?.into();
        let memo: String = env.get_string(&memo)?.into();
        let spend_path: String = env.get_string(&spend_params_path)?.into();
        let output_path: String = env.get_string(&output_params_path)?.into();

        if !(0..=u32::MAX as i64).contains(&block_height) {
            return Err(format!("block_height out of u32 range: {block_height}").into());
        }
        if amount_sat < 0 {
            return Err(format!("amount out of range: {amount_sat}").into());
        }

        // wallet_json carries the plaintext seed + mnemonic over the JNI
        // boundary: wrap in Zeroizing so its buffer is wiped on drop (the
        // kit's WalletData itself derives ZeroizeOnDrop).
        let wallet_json = zeroize::Zeroizing::new(wallet_json);
        let mut wallet: WalletData = serde_json::from_str(&wallet_json)?;

        // Fast-fail before the expensive (~50 MB) parameter load: with no
        // notes to spend there is nothing to prove. Mirrors the message the
        // builder would produce so callers see one consistent error.
        if wallet.unspent_notes.is_empty() {
            return Err("insufficient shield balance: no notes available".into());
        }

        let spend_bytes = std::fs::read(&spend_path)
            .map_err(|e| format!("cannot read spend params at {spend_path}: {e}"))?;
        let output_bytes = std::fs::read(&output_path)
            .map_err(|e| format!("cannot read output params at {output_path}: {e}"))?;
        let prover = verify_and_load_params(&output_bytes, &spend_bytes)?;

        let result = create_shield_transaction(
            &mut wallet,
            &to_address,
            amount_sat as u64,
            &memo,
            block_height as u32,
            &prover,
        )?;

        let out = serde_json::to_string(&result)?;
        let jstr = env.new_string(out)?;
        Ok(jstr.into_raw())
    })
    .unwrap_or(std::ptr::null_mut())
}

/// Select which shield notes would be spent for an amount — the exact same
/// selection + fee the builder would charge. Pure: no params, no network.
///
/// This powers `--subtract-fee` on the Java side: fee depends on how many
/// notes get selected, so Java loops this call to a fixpoint
/// (`fee -> sendAmount = budget - fee -> re-select`) before building.
///
/// Inputs:
/// - `notes_json` — JSON array of the kit's `SerializedNote` shape,
/// - `amount_sat` — target send amount (recipient-side),
/// - `transparent_outs` / `sapling_outs` — output shape (`(0,2)` shield dest
///   or `(1,2)` transparent dest).
///
/// Returns `{indexes, fee, total}` as JSON (kit's `ShieldSelection`).
///
/// Java signature: `static native String nativeSelectShieldNotes(String notesJson, long amountSat, long transparentOuts, long saplingOuts)`
#[no_mangle]
pub extern "system" fn Java_dev_jpivx_wallet_crypto_ShieldKeys_nativeSelectShieldNotes(
    mut env: JNIEnv,
    _class: JClass,
    notes_json: JString,
    amount_sat: jlong,
    transparent_outs: jlong,
    sapling_outs: jlong,
) -> jstring {
    guard(&mut env, |env| {
        let notes_json: String = env.get_string(&notes_json)?.into();
        if amount_sat < 0 || transparent_outs < 0 || sapling_outs < 0 {
            return Err("negative amount/output counts".into());
        }
        let notes: Vec<SerializedNote> = serde_json::from_str(&notes_json)?;
        let selection = select_shield_notes(
            &notes,
            amount_sat as u64,
            transparent_outs as u64,
            sapling_outs as u64,
        )?;
        // ShieldSelection has no serde derive in the kit — hand-roll the JSON.
        let out = serde_json::json!({
            "indexes": selection.indexes,
            "fee": selection.fee,
            "total": selection.total,
        })
        .to_string();
        let jstr = env.new_string(out)?;
        Ok(jstr.into_raw())
    })
    .unwrap_or(std::ptr::null_mut())
}

// ---------------------------------------------------------------------------
// Golden-vector tests (cross-checked against pivx-wallet-kit's own tests)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use pivx_wallet_kit::keys;

    /// Same BIP39 vector as `pivx-wallet-kit/tests/integration.rs`.
    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /// Real mainnet fixture from `pivx-wallet-kit/tests/fixtures/`
    /// (`69dc1691...`, pure shield: 1 spend + 2 outputs).
    const TX_SHIELD_HEX: &str =
        include_str!("../../../../../pivx-wallet-kit/tests/fixtures/tx_shield.hex");

    fn test_extfvk() -> String {
        let mnemonic = bip39::Mnemonic::parse_normalized(TEST_MNEMONIC).unwrap();
        let mut bip39_seed = mnemonic.to_seed("");
        let mut seed32 = [0u8; 32];
        seed32.copy_from_slice(&bip39_seed[..32]);
        bip39_seed.iter_mut().for_each(|b| *b = 0);
        let extsk = keys::spending_key_from_seed(&seed32, 0).unwrap();
        keys::encode_extfvk(&keys::full_viewing_key(&extsk))
    }

    #[test]
    fn print_golden_vectors() {
        let extfvk = test_extfvk();
        let default_addr = keys::get_default_address(&extfvk).unwrap();
        let (idx0, addr0) = keys::shield_address_at(&extfvk, 0).unwrap();
        let (idx_next, addr_next) = keys::shield_address_at(&extfvk, idx0 + 1).unwrap();

        eprintln!("GOLDEN extfvk          = {extfvk}");
        eprintln!("GOLDEN default address = {default_addr}");
        eprintln!("GOLDEN at(0)           = {idx0} {addr0}");
        eprintln!("GOLDEN next            = {idx_next} {addr_next}");

        assert!(extfvk.starts_with("pxviews"));
        assert!(default_addr.starts_with("ps1"));
        assert_eq!(default_addr, addr0, "shield_address_at(0) == default address");
        assert!(idx_next > idx0);
        assert_ne!(addr_next, addr0);
    }

    /// Mirrors `handle_blocks_with_unrelated_key_advances_tree_and_extracts_nullifier`
    /// in the kit's integration tests, and prints the golden nullifier plus tree
    /// lengths so the Java JUnit test can assert equality.
    #[test]
    fn print_handle_blocks_golden_vectors() {
        use pivx_wallet_kit::{checkpoints, sapling, simd};

        let extfvk = test_extfvk();
        let tree_hex = checkpoints::MAINNET_CHECKPOINTS[0].1;
        let tx_bytes = simd::hex::hex_string_to_bytes(TX_SHIELD_HEX.trim());
        let block = sapling::sync::ShieldBlock {
            height: 5_000_000,
            txs: vec![tx_bytes],
        };

        let result = sapling::sync::handle_blocks(tree_hex, vec![block], &extfvk, vec![]).unwrap();

        eprintln!("GOLDEN first-tree-len  = {}", tree_hex.len());
        eprintln!("GOLDEN nullifier[0]    = {}", result.nullifiers[0]);
        eprintln!("GOLDEN tree-after-len  = {}", result.commitment_tree.len());

        // Unrelated key: nothing decrypted, one spend nullifier surfaced.
        assert!(result.new_notes.is_empty());
        assert_eq!(result.nullifiers.len(), 1);
        assert_ne!(result.commitment_tree, tree_hex);
    }

    /// Full offline E2E of the shield-send path: craft a self-owned note,
    /// witness it on a fresh tree, wrap the wallet in its JSON wire form
    /// (exactly what Java passes over JNI), and build + sign a real
    /// Groth16-proven shield→shield tx. The tx is validly signed but not
    /// broadcastable to mainnet (anchor root is unknown to the chain) —
    /// the point is to exercise selection, proving, signing, serialization.
    ///
    /// Gated: runs only when the Sapling params exist locally at
    /// `~/.pivx-wallet/params/` (downloaded by jpivx's `send shield` on first
    /// use); otherwise skipped silently.
    #[test]
    fn build_real_shield_tx_offline() {
        use ff::Field;
        use incrementalmerkletree::frontier::CommitmentTree;
        use incrementalmerkletree::witness::IncrementalWitness;
        use pivx_wallet_kit::{simd, wallet as kit_wallet};
        use ::sapling::Node;

        let home = std::env::var("HOME").unwrap();
        let spend_path = format!("{home}/.pivx-wallet/params/sapling-spend.params");
        let output_path = format!("{home}/.pivx-wallet/params/sapling-output.params");
        let (Ok(spend_bytes), Ok(output_bytes)) =
            (std::fs::read(&spend_path), std::fs::read(&output_path))
        else {
            eprintln!("SKIP build_real_shield_tx_offline: params not at {spend_path}");
            return;
        };
        let prover = pivx_wallet_kit::sapling::prover::verify_and_load_params(
            &output_bytes,
            &spend_bytes,
        )
        .unwrap();

        // Wallet from the shared test vector, height arbitrary.
        let mut wallet = kit_wallet::import_wallet(TEST_MNEMONIC, 5_000_000).unwrap();
        let extsk = keys::decode_extsk(&wallet.derive_extsk_encoded().unwrap()).unwrap();
        let dfvk = extsk.to_diversifiable_full_viewing_key();
        let (_idx, our_addr) = dfvk.default_address();

        // Craft a self-owned note worth 10_000_000 sat.
        let note = ::sapling::note::Note::from_parts(
            our_addr,
            ::sapling::value::NoteValue::from_raw(10_000_000),
            ::sapling::note::Rseed::BeforeZip212(jubjub::Fr::random(rand_core::OsRng)),
        );

        // Witness it on a fresh tree (any root is fine for build-only).
        let mut tree = CommitmentTree::<Node, 32>::empty();
        tree.append(Node::from_cmu(&note.cmu())).unwrap();
        let witness = IncrementalWitness::<Node, 32>::from_tree(tree);
        let nk = dfvk.to_nk(pivx_primitives::zip32::Scope::External);
        let nf = note.nf(&nk, witness.witnessed_position().into());

        let mut buf = Vec::new();
        pivx_primitives::merkle_tree::write_incremental_witness(&witness, &mut buf).unwrap();
        wallet.unspent_notes.push(pivx_wallet_kit::wallet::SerializedNote {
            note: serde_json::to_value(&note).unwrap(),
            witness: simd::hex::bytes_to_hex_string(&buf),
            nullifier: simd::hex::bytes_to_hex_string(&nf.0),
            memo: None,
            height: 5_000_000,
        });

        // JSON round-trip: what Java's Jackson passes over JNI must deserialize
        // into the kit's WalletData without loss.
        let wallet_json = serde_json::to_string(&wallet).unwrap();
        let mut wallet_rt: pivx_wallet_kit::wallet::WalletData = serde_json::from_str(&wallet_json).unwrap();

        let dest = keys::get_default_address(&wallet.extfvk).unwrap();
        let result = pivx_wallet_kit::sapling::builder::create_shield_transaction(
            &mut wallet_rt,
            &dest,
            5_000_000,
            "jpivx offline test",
            5_000_001,
            &prover,
        )
        .unwrap();

        eprintln!("GOLDEN shield txhex  = {}...", &result.txhex[..80]);
        eprintln!("GOLDEN shield nf[0]  = {}", result.nullifiers[0]);
        eprintln!("GOLDEN shield fee    = {}", result.fee);
        eprintln!("GOLDEN note json     = {}", serde_json::to_string(&note).unwrap());
        eprintln!("GOLDEN witness hex   = {}", simd::hex::bytes_to_hex_string(&buf));

        // Must look like a real tx: parse it back and inspect the bundle.
        let tx = pivx_primitives::transaction::Transaction::read(
            std::io::Cursor::new(simd::hex::hex_string_to_bytes(&result.txhex)),
            pivx_primitives::consensus::BranchId::Sapling,
        )
        .unwrap();
        let bundle = tx.sapling_bundle().expect("sapling bundle present");
        assert_eq!(bundle.shielded_spends().len(), 1, "one spend (single note)");
        assert_eq!(bundle.shielded_outputs().len(), 2, "dest + change");
        assert_eq!(result.amount, 5_000_000);
        assert_eq!(result.nullifiers.len(), 1);
    }
}
