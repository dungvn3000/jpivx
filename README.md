# jpivx — PIVX Wallet Kit (Java)

A Java library for building PIVX wallets. Pure-Java transparent layer (BIP39/BIP32, P2PKH addresses, message signing, v1 transaction building) ported from the Rust [pivx-wallet-kit](https://github.com/PIVX-Labs/pivx-wallet-kit). Shield (Sapling) key derivation, sync, and spending are provided through a JNI bridge to the Rust kit.

- **Java 21**, BouncyCastle crypto (no bitcoinj — BIP32/BIP39/ECDSA implemented internally)
- Cross-verified **byte-identical** with the Rust kit (same addresses, same signatures, same txhex, same shield extfvk/addresses)
- No wallet storage or CLI — consumers own their persistence layer
- JNI shield library is bundled as a resource and extracted at runtime

---

## Getting Started

### Maven

```xml
<dependency>
    <groupId>dev.jpivx</groupId>
    <artifactId>wallet-kit</artifactId>
    <version>0.0.1-SNAPSHOT</version>
</dependency>
```

### Gradle

```kotlin
implementation("dev.jpivx:wallet-kit:0.0.1-SNAPSHOT")
```

### Build from source

```bash
./mvnw package
# → target/wallet-kit.jar (transparent-only if the native shield lib is missing)

# With the JNI shield library (requires cargo + the pivx-wallet-kit source
# available at the relative path declared in native/shield-jni/Cargo.toml):
./mvnw package -Pnative
```

Requirements: JDK 21+, Maven 3.9+ (wrapper included); Rust toolchain (cargo) for the shield JNI bridge.

---

## Usage

### BIP39 — Mnemonic & Seed

```java
// Generate a new 24-word mnemonic
List<String> words = BIP39Service.generateMnemonic();
String mnemonic = String.join(" ", words);

// Parse an existing mnemonic
List<String> parsed = BIP39Service.parse(mnemonic);
byte[] seed = BIP39Service.toSeed(parsed); // 64-byte BIP39 seed
```

### BIP32 — Transparent Key Derivation

```java
// Derive key at m/44'/119'/0'/0/0 (default receive address)
TransparentKeys.TransparentKey key =
    TransparentKeys.transparentKeyFromBip39Seed(seed, 0, 0);

String address = key.address(); // "DPo9TNvPwy2ZfmVM3CRCxbBvh6NojguWXJ"
byte[] pubkey  = key.pubkey();
byte[] privkey = key.privkey();

// Convenience — default address directly from mnemonic
String defaultAddress = TransparentKeys.getTransparentAddress(mnemonic);
```

### Addresses

```java
// Encode/decode a transparent P2PKH address
byte[] script  = PivxAddress.addressToP2pkhScript("DPo9TNv...");
byte[] hash160 = PivxAddress.addressToHash160("DPo9TNv...");
String address = PivxAddress.hash160ToAddress(hash160);

// Shield address (requires JNI library)
boolean available = ShieldKeys.isAvailable();
String extfvk = ShieldKeys.extfvk(seed);                     // "pxviews1..."
String shieldAddr = ShieldKeys.defaultShieldAddress(seed);    // "ps124f3d..."
```

### Message Signing

```java
// Sign a message (PIVX Core-compatible base64 signature)
String sig = PivxMessageSigner.signMessage(privkey, "Hello PIVX");

// Verify
boolean ok = PivxMessageSigner.verifyMessage("DPo9TNv...", "Hello PIVX", sig);
```

### Building a Transparent Transaction

```java
// Automatic UTXO selection (Branch-and-Bound changeless match first,
// Knapsack with change as fallback — see CoinSelector)
List<Utxo> utxos = ...; // from BlockbookClient or your own source
TransparentTransactionResult result = RawTransparentBuilder.createRawTransparentTransaction(
    utxos, seed, "DRecipientAddress...", 100_000_000L /* sats */);

String txhex = result.txhex();
long feeSat  = result.fee();

// Spend from a specific HD index slot
TransparentTransactionResult result2 = RawTransparentBuilder.createRawTransparentTransactionFromUtxos(
    seed, 0 /* change */, 3 /* hdIndex */, utxos, "DRecipientAddress...", 100_000_000L);

// Multi-index: each UTXO signed with its own HD key (utxo.hdIndex())
TransparentTransactionResult result3 = RawTransparentBuilder.createRawTransparentTransactionMultiIndex(
    utxos, seed, "DRecipientAddress...", 100_000_000L);
```

### Fee Estimation

```java
// 10 sat/byte, v1 P2PKH (~150 bytes/input, ~34 bytes/output)
long feeSat = FeeEstimator.estimateRawTransparentFee(inputCount, outputCount);

// Shield fee (kit's fees::estimate_fee): 1000 sat/byte over a size model of
// (s_out×948 + s_in×384 + t_in×180 + t_out×34 + 100) bytes
// e.g. 1-spend shield→shield (2 sapling outs) = 2,380,000 sat (0.0238 PIV)
long shieldFee = FeeEstimator.estimateFee(tIn, tOut, sIn, sOut);
```

### Network Clients

```java
// Fetch UTXOs from Blockbook
BlockbookClient blockbook = new BlockbookClient("https://explorer.pivxla.bz");
List<Utxo> utxos = blockbook.getUtxos("DPo9TNv...");         // confirmed only
List<Utxo> all   = blockbook.getUtxos("DPo9TNv...", false);  // include mempool

// Broadcast a signed transaction
String txid = blockbook.sendTransaction(txhex);

// PIVX JSON-RPC node
PivxRpcClient rpc = new PivxRpcClient("https://rpc.pivxla.bz/mainnet", "user", "pass");
String txid2 = rpc.sendRawTransaction(txhex);
int tip = rpc.getBlockCount();
```

### Shield Sync (JNI)

```java
// ShieldState holds the three fields that change during sync
ShieldState state = new ShieldState(
    birthdayHeight,   // last synced block (start here)
    "",               // commitment tree (empty on first sync)
    List.of()         // unspent notes (empty on first sync)
);

ShieldNodeClient node = new ShieldNodeClient("https://rpc.pivxla.bz/mainnet");

int processed = ShieldSyncService.syncShield(
    seed, state, node,
    ShieldSyncService.DEFAULT_BATCH_BLOCKS,
    s -> saveState(s),                          // persist after each batch
    (height, tip) -> System.out.printf("%.0f%%\n", 100.0 * height / tip)
);

List<SerializedNote> notes = state.getUnspentNotes();
long shieldBalanceSat = state.getShieldBalance();
```

### Shield Send (JNI + Groth16)

```java
// On first use: downloads Sapling proving params (~49 MB) and verifies SHA256
SaplingParams params = new SaplingParams(SaplingParams.defaultDir());
if (!params.present()) {
    // Mirror derived from the node REST URL: https://rpc.pivxla.bz/mainnet → https://pivxla.bz
    String baseUrl = SaplingParams.deriveParamsBaseUrl("https://rpc.pivxla.bz/mainnet");
    params.ensureLoaded(baseUrl, 10); // blocks until downloaded; progress every 10 MB
}

// One-call send: mnemonic + synced ShieldState → signed tx
ShieldTxResult result = ShieldSendService.createTransaction(
    mnemonic, birthdayHeight, state,
    "ps124f3dxh...",   // recipient: ps1... (shield→shield) or D... (deshield)
    5_000_000L,        // amount in sats
    "memo",            // optional memo ("" for none)
    chainTip + 1,      // expiry / anchor context
    params);

String txhex = result.txhex();

// After broadcasting: drop the spent notes and persist the state
state.removeSpentNotes(result.nullifiers());
saveState(state);

// Optional — subtract-fee sends: find the recipient amount such that
// recipient + fee == budget (fee depends on note selection, solved by fixpoint)
long sendAmount = ShieldSendService.resolveSubtractFeeAmount(
    state.getUnspentNotes(), budgetSat, "ps124f3dxh...");
```

Lower-level entry points remain available: `ShieldSendService.buildWalletJson(...)`
produces the kit's `WalletData` JSON, and `ShieldKeys.createShieldTransaction(...)`
takes it directly for full control over the JNI call.

---

## Architecture

```
jpivx/
├── native/shield-jni/           Rust JNI bridge (cdylib libjpivx_shield_jni)
│   └── src/lib.rs               JNI exports → pivx_wallet_kit::keys (Sapling)
├── native/build-native.sh       cargo build + copy cdylib into resources
└── src/main/java/dev/jpivx/wallet/
    ├── core/                    PivxParams, PivAmount, FeeEstimator, VarInt, Utxo
    ├── crypto/                  BIP39Service, BIP32Service, TransparentKeys,
    │                            PivxAddress, PivxMessageSigner, ShieldKeys (JNI)
    ├── internal/                Base58, ECKey, HDKeyDerivation, DeterministicKey,
    │                            ChildNumber, MnemonicCode, Sha256Hash, ByteUtil
    ├── tx/                      RawTransparentBuilder (v1 P2PKH, SIGHASH_ALL),
    │                            CoinSelector (BnB + Knapsack), SpentOutpoint,
    │                            TransparentTransactionResult
    ├── shield/                  ShieldState, ShieldSyncService, ShieldSendService,
    │                            ShieldStreamParser, ShieldBlock, HandleBlocksResult,
    │                            SerializedNote, ShieldSelection, ShieldTxResult,
    │                            SaplingParams
    └── network/                 BlockbookClient (REST), BlockbookParser,
                                 PivxRpcClient (JSON-RPC),
                                 ShieldNodeClient (node REST: getshielddata)
```

### Cross-verification with the Rust kit

The Java implementation is **byte-compatible** with the Rust `pivx-wallet-kit`:
- Same BIP39 seed → same transparent address (`DPo9TNvPwy2ZfmVM3CRCxbBvh6NojguWXJ`)
- Same mnemonic + message → same base64 signature (RFC6979 deterministic nonce)
- Same UTXO set + key → same txhex (verified via golden vectors captured from Rust)
- Same mnemonic → same shield extfvk (`pxviews1...`) and default shield address
  (`ps124f3dxh...` for the shared BIP39 test vector) — golden values asserted in
  `ShieldKeysTest`, produced by the kit itself over JNI

---

## Default network endpoints

| Service | URL | Auth |
|---|---|---|
| Blockbook (UTXO fetch + broadcast) | `https://explorer.pivxla.bz` | None |
| PIVX JSON-RPC (alternative broadcast) | `https://rpc.pivxla.bz/mainnet` | User/pass |

---

## Limitations

- **Full shield lifecycle works**: derive addresses → sync (scan, decrypt, witness)
  → send (Groth16-proven spends to `ps1...` or `D...`). Remaining gaps: no
  transparent→shield shielding builder, no reorg handling (same semantics as the
  Rust kit), and proving params (~49 MB) must be downloadable at first use.
- Native lib is per-platform: build on each target platform
  (`native/build-native.sh` detects `macos`/`linux`/`windows` × `aarch64`/`x86_64`).

### Known upstream quirk (deliberate divergence)

`ShieldStreamParser` groups footer-format streams strictly (txs always belong
to the block of their closing 0x5d footer). The Rust kit's
`sync::parse_next_blocks` instead attaches txs to the last already-committed
block of the batch when both a committed block and new txs coexist —
mis-grouping pure footer streams beyond the first block. jpivx follows
MyPIVXWallet's `BinaryShieldSyncer` semantics (which match what PIVX Core
REST actually serves); all other wire details are byte-identical with the kit.

---

## License

[MIT](LICENSE) (same as the upstream Rust `pivx-wallet-kit`).
