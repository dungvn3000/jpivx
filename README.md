# jpivx — PIVX Wallet Kit (Java)

A Java library for building PIVX wallets. Pure-Java transparent layer (BIP39/BIP32, P2PKH addresses, message signing, v1 transaction building) ported from the Rust [pivx-wallet-kit](https://github.com/PIVX-Labs/pivx-wallet-kit). Shield (Sapling) key derivation, sync, spending, and shielding (transparent→shield) are provided through a JNI bridge to the Rust kit.

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

// Or pick the length: 12, 15, 18, 21, or 24 words
List<String> short12 = BIP39Service.generateMnemonic(12);

// Parse an existing mnemonic (whitespace-tolerant, case-insensitive —
// words are trimmed and lower-cased before seed derivation)
List<String> parsed = BIP39Service.parse(mnemonic);
byte[] seed = BIP39Service.toSeed(parsed); // 64-byte BIP39 seed (NFKD per BIP39)
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
// Encode/decode a transparent P2PKH address. Decoding validates the
// Base58Check version byte, so foreign-chain addresses (Bitcoin, Dash,
// PIVX staking/testnet) throw IllegalArgumentException instead of being
// accepted as a send destination.
byte[] script  = PivxAddress.addressToP2pkhScript("DPo9TNv...");
byte[] hash160 = PivxAddress.addressToHash160("DPo9TNv...");
String address = PivxAddress.hash160ToAddress(hash160);

// Shield address (requires JNI library)
boolean available = ShieldKeys.isAvailable();
ShieldKeys.Checkpoint cp = ShieldKeys.checkpoint(birthdayHeight); // sync starting point
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

// Several recipients in one transaction — a batch payment, or splitting a
// UTXO into spendable pieces without chaining one tx (and one fee, and one
// confirmation wait) per piece. Change returns to the first input's address.
TransparentTransactionResult batch = RawTransparentBuilder.createRawTransparentTransaction(
        utxos, seed, List.of(new Recipient("DAlice...", 100_000_000L),
                             new Recipient("DBob...",   250_000_000L)));

// split() lays out N equal pieces (the last absorbs the rounding remainder)
TransparentTransactionResult chunks = RawTransparentBuilder.createRawTransparentTransaction(
        utxos, seed, RawTransparentBuilder.split(ownAddress, 400_000_000L, 4));

// Multi-index: each UTXO signed with its own HD key (utxo.hdIndex());
// defaults to the external branch (change=0). Pass the branch explicitly
// to spend internal-branch coins (all UTXOs must be on that one branch):
TransparentTransactionResult result3 = RawTransparentBuilder.createRawTransparentTransactionMultiIndex(
    utxos, seed, "DRecipientAddress...", 100_000_000L);
TransparentTransactionResult result4 = RawTransparentBuilder.createRawTransparentTransactionMultiIndex(
    utxos, seed, "DRecipientAddress...", 100_000_000L, 1 /* change branch */);
```

Change below the 546-sat dust threshold is folded into the fee (nodes reject
sub-dust outputs as nonstandard), and `result.fee()` always reports the fee
actually paid — including any changeless-selection surplus donated to miners.

### Fee Estimation

```java
// 10 sat/byte, v1 P2PKH (~150 bytes/input, ~34 bytes/output)
long feeSat = FeeEstimator.estimateRawTransparentFee(inputCount, outputCount);

// Shield fee (kit's fees::estimate_fee): 1000 sat/byte over a size model of
// (s_out×948 + s_in×384 + t_in×180 + t_out×34 + 100) bytes
// e.g. 1-spend shield→shield (2 sapling outs) = 2,380,000 sat (0.0238 PIV)
//      1-input transparent→shield             = 2,176,000 sat (0.0218 PIV)
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

The commitment tree is **consensus state**: a tree accumulated from an arbitrary
starting point yields an anchor no node ever had, and every spend built against
it is rejected with `bad-txns-shielded-requirements-not-met`. So a wallet seeds
its tree from an embedded checkpoint — never from an empty string — exactly as
the kit's own `create_wallet_from_mnemonic` does:

```java
// Snap the birthday down to the nearest checkpoint and start from its tree.
// (The empty tree "000000" is the first checkpoint only, before Sapling activation.)
ShieldKeys.Checkpoint cp = ShieldKeys.checkpoint(birthdayHeight);

// ShieldState holds the three fields that change during sync
ShieldState state = new ShieldState(
    cp.height(),          // last synced block (start here)
    cp.commitmentTree(),  // commitment tree as of that height
    List.of()             // unspent notes (empty on first sync)
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

// Optional — subtract-fee / send-max: the largest recipient amount with
// recipient + fee <= budget (== budget when it's fully consumable; the fee
// depends on note selection, so it's solved by binary search against the
// kit's own selection)
long sendAmount = ShieldSendService.resolveSubtractFeeAmount(
    state.getUnspentNotes(), budgetSat, "ps124f3dxh...");

// Send-many: pay several recipients — any mix of ps1... and D... — in ONE
// transaction. Each shield output carries its own memo and is encrypted to
// its recipient alone; change returns to the wallet's default shield address.
ShieldTxResult batch = ShieldSendService.createTransaction(
    mnemonic, birthdayHeight, state,
    List.of(new ShieldRecipient("ps124f3dxh...", 2_000_000L, "memo one"),
            new ShieldRecipient("ps1qqther...",  3_000_000L, "memo two"),
            new ShieldRecipient("DPo9TNv...",    1_000_000L)), // deshield leg
    chainTip + 1, params);
```

### Unshield: Shield → Transparent (deshield)

Same entry point — only the destination changes. A `D...` address turns the
send into a deshield: the recipient gets a transparent output, while change
(and the inputs) stay shielded. Groth16 params are still required because the
tx spends shield notes.

```java
ShieldTxResult result = ShieldSendService.createTransaction(
    mnemonic, birthdayHeight, state,
    "DPo9TNvPwy2ZfmVM3CRCxbBvh6NojguWXJ",  // D... destination → deshield
    5_000_000L,        // amount in sats
    "",                // memo is ignored for transparent destinations
    chainTip + 1,
    params);

blockbook.sendTransaction(result.txhex());
state.removeSpentNotes(result.nullifiers());
saveState(state);

// Send-max works the same — the D... destination makes the solver charge
// the deshield fee shape (one extra transparent output, +34,000 sat):
long sendAmount = ShieldSendService.resolveSubtractFeeAmount(
    state.getUnspentNotes(), state.getShieldBalance(), "DPo9TNv...");
```

Lower-level entry points remain available: `ShieldSendService.buildWalletJson(...)`
produces the kit's `WalletData` JSON, and `ShieldKeys.createShieldTransaction(...)`
takes it directly for full control over the JNI call.

### Shielding: Transparent → Shield (JNI + Groth16)

The mirror image of a shield send: transparent UTXOs in, a `ps1...` note out.
Needs the same Sapling params (the tx carries a real output bundle).

```java
List<Utxo> utxos = blockbook.getUtxos(transparentAddress);

TransparentTransactionResult result = ShieldingService.createTransaction(
    mnemonic, utxos,
    "ps124f3dxh...",   // shield destination (a D... address is rejected)
    100_000_000L,      // amount in sats
    chainTip,          // expiry context
    params);

String txhex = result.txhex();
result.spent();        // UTXOs consumed — drop them from your UTXO set

// Preview the exact fee the builder will charge for this amount (the kit's
// own selection over JNI — throws the same "Insufficient public balance"
// the build would), and solve send-max: the largest amount with
// recipient + fee <= budget (== budget when it's fully consumable):
long fee        = ShieldingService.selectionFee(utxos, 100_000_000L);
long sendAmount = ShieldingService.resolveSubtractFeeAmount(utxos, totalBalanceSat);
```

Constraints inherited from the Rust kit's `create_shielding_transaction`:

- every input is signed with the key at `m/44'/119'/0'/0/0`, so all UTXOs must
  sit on the wallet's default transparent address — a UTXO tagged with another
  `hdIndex` is rejected rather than signed invalidly (checked in the facade
  and again natively, so the lower-level `ShieldKeys` path is covered too);
- change comes back as a **transparent** output to that same address, not as a
  shield note;
- no memo (the kit hardcodes an empty memo on the shield output);
- UTXO selection is largest-first, and the fee is charged for the shape
  `(n transparent inputs, 0 transparent outputs, 0 sapling spends, 2 sapling
  outputs)` — 2,176,000 sat for a single input. Selection and fee come from
  the kit's `select_shielding_utxos` over JNI, never re-implemented in Java.

The parsed Groth16 prover is cached natively per parameter-path pair, so only
the first build in a process pays the ~50 MB read + SHA256 + parse.

Lower-level: `ShieldSendService.buildWalletJson(mnemonic, birthday, state, utxos)`
produces the UTXO-carrying `WalletData` JSON, and
`ShieldKeys.createShieldingTransaction(...)` takes it directly — the signing
seed is derived natively from the wallet's own mnemonic, and foreign
`hd_index` tags are rejected natively on this path too.

---

## Architecture

```
jpivx/
├── native/shield-jni/           Rust JNI bridge (cdylib libjpivx_shield_jni)
│   └── src/lib.rs               JNI exports → pivx_wallet_kit keys/sync/builders
│                                (Sapling + shielding; cached Groth16 prover;
│                                checkpoint lookup)
├── native/build-native.sh       cargo build + copy cdylib into resources
└── src/main/java/dev/jpivx/wallet/
    ├── core/                    PivxParams, PivAmount, FeeEstimator, VarInt, Utxo
    ├── crypto/                  BIP39Service, BIP32Service, TransparentKeys,
    │                            PivxAddress, PivxMessageSigner, ShieldKeys (JNI,
    │                            incl. the embedded commitment-tree checkpoints)
    ├── internal/                Base58, ECKey, HDKeyDerivation, DeterministicKey,
    │                            ChildNumber, MnemonicCode, Sha256Hash, ByteUtil
    ├── tx/                      RawTransparentBuilder (v1 P2PKH, SIGHASH_ALL,
    │                            single- and multi-recipient), Recipient,
    │                            CoinSelector (BnB + Knapsack), SpentOutpoint,
    │                            TransparentTransactionResult
    ├── shield/                  ShieldState, ShieldSyncService, ShieldSendService,
    │                            ShieldingService (transparent→shield),
    │                            SubtractFee (shared send-max solver),
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
- Same UTXO set + key → same txhex (verified via golden vectors captured from Rust).
  The multi-recipient entry point is Java-only — the kit has no counterpart — and
  is pinned to the verified path by asserting that a one-recipient call produces
  byte-identical hex to `createRawTransparentTransactionMultiIndex`
- Same mnemonic → same shield extfvk (`pxviews1...`) and default shield address
  (`ps124f3dxh...` for the shared BIP39 test vector) — golden values asserted in
  `ShieldKeysTest`, produced by the kit itself over JNI
- Shield and shielding sends assert the kit's golden fees and tx shapes on both
  sides of the bridge (`ShieldSendFullJniTest` / `ShieldingJniTest` in Java,
  `build_real_shield_tx_offline` / `build_real_shielding_tx_offline` in Rust)

---

## Default network endpoints

| Service | URL | Auth |
|---|---|---|
| Blockbook (UTXO fetch + broadcast) | `https://explorer.pivxla.bz` | None |
| PIVX JSON-RPC (alternative broadcast) | `https://rpc.pivxla.bz/mainnet` | User/pass |

---

## Limitations

- **Full shield lifecycle works**: derive addresses → sync (scan, decrypt, witness)
  → send (Groth16-proven spends to `ps1...` or `D...`) → shield transparent coins
  (`ShieldingService`, t→z). Remaining gaps: shielding spends only UTXOs on the
  default address `m/44'/119'/0'/0/0` and returns change transparently (kit
  behaviour), no reorg handling (same semantics as the Rust kit), and proving
  params (~49 MB) must be downloadable at first use.
- Native lib is per-platform: build on each target platform
  (`native/build-native.sh` detects `macos`/`linux`/`windows` × `aarch64`/`x86_64`).

### Known upstream quirk (deliberate divergence)

`ShieldStreamParser` groups footer-format streams strictly (txs always belong
to the block of their closing 0x5d footer), telling the two marker formats
apart by payload length (9-byte footer vs 5-byte header) so an empty block
cannot shift later grouping. The Rust kit's `sync::parse_next_blocks` instead
attaches txs to the last already-committed block of the batch when both a
committed block and new txs coexist — mis-grouping pure footer streams beyond
the first block. jpivx follows MyPIVXWallet's `BinaryShieldSyncer` semantics
(which match what PIVX Core REST actually serves); all other wire details are
byte-identical with the kit. Truncated streams (cut mid-length, mid-packet, or
with txs missing their footer) raise `IOException` rather than being treated
as clean EOF.

---

## License

[MIT](LICENSE) (same as the upstream Rust `pivx-wallet-kit`).
