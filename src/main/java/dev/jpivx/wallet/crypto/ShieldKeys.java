package dev.jpivx.wallet.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Locale;
import java.util.zip.CRC32;

/**
 * Sapling shield key/address derivation via JNI to the Rust
 * {@code pivx-wallet-kit}.
 *
 * <p>Native counterpart: {@code native/shield-jni} (cdylib
 * {@code libjpivx_shield_jni}). The library is located in this order:
 * <ol>
 *   <li>system property {@code jpivx.shield.lib} (absolute path),</li>
 *   <li>environment variable {@code JPIVX_SHIELD_LIB} (absolute path),</li>
 *   <li>bundled JAR resource {@code /native/<os>-<arch>/libjpivx_shield_jni.*},
 *       extracted to a temp file and loaded.</li>
 * </ol>
 *
 * <p>If none of the above succeed the class still initialises — every entry
 * point then throws {@link IllegalStateException} from {@link #requireAvailable()},
 * and {@link #isAvailable()} returns {@code false}. This keeps jpivx fully
 * usable for transparent-only wallets on machines without the native build.
 *
 * <p>Derivation is byte-identical with the Rust kit: the first 32 bytes of the
 * 64-byte BIP39 seed feed ZIP32 {@code m/32'/119'/0'}, giving the extfvk and
 * the default diversified {@code ps1...} payment address.
 */
public final class ShieldKeys {

    private static final String LIB_PROPERTY = "jpivx.shield.lib";
    private static final String LIB_ENV = "JPIVX_SHIELD_LIB";
    private static final String LIB_BASE_NAME = "jpivx_shield_jni";

    private static final boolean AVAILABLE;
    private static final String UNAVAILABLE_REASON;

    static {
        String reason;
        boolean ok;
        try {
            loadNativeLibrary();
            ok = true;
            reason = null;
        } catch (Throwable t) {
            ok = false;
            reason = t.getMessage();
        }
        AVAILABLE = ok;
        UNAVAILABLE_REASON = reason;
    }

    private ShieldKeys() {
        throw new AssertionError("no instances");
    }

    /** A diversified shield address plus the diversifier index actually used. */
    public record ShieldAddress(long index, String address) {}

    /** True when the native shield library was found and linked. */
    public static boolean isAvailable() {
        return AVAILABLE;
    }

    /** Why the native library is unavailable (null when available). */
    public static String unavailableReason() {
        return UNAVAILABLE_REASON;
    }

    private static void requireAvailable() {
        if (!AVAILABLE) {
            throw new IllegalStateException(
                    "Shield native library not loaded (build with "
                            + "native/build-native.sh or ./mvnw package -Pnative): "
                            + UNAVAILABLE_REASON);
        }
    }

    /**
     * Derive the bech32-encoded extended full viewing key from a 64-byte
     * BIP39 seed (only the first 32 bytes are used, matching the Rust kit).
     */
    public static String extfvk(byte[] bip39Seed) {
        requireAvailable();
        return nativeExtfvk(bip39Seed);
    }

    /**
     * Derive the default diversified shield payment address ({@code ps1...})
     * from a 64-byte BIP39 seed. Equal to {@code shieldAddressAt(extfvk, 0)}.
     */
    public static String defaultShieldAddress(byte[] bip39Seed) {
        requireAvailable();
        return nativeDefaultShieldAddress(bip39Seed);
    }

    /**
     * Derive the shield address at (or after) {@code startIndex}. ~50% of
     * diversifier indices are invalid per the Sapling spec, so the native side
     * scans forward and reports the index it actually used
     * ({@link ShieldAddress#index()} &ge; {@code startIndex}).
     *
     * @param encodedExtfvk bech32 extfvk from {@link #extfvk(byte[])}
     * @param startIndex    diversifier search start (0..4294967295)
     */
    public static ShieldAddress shieldAddressAt(String encodedExtfvk, long startIndex) {
        requireAvailable();
        String[] pair = nativeShieldAddressAt(encodedExtfvk, startIndex);
        return new ShieldAddress(Long.parseLong(pair[0]), pair[1]);
    }

    /**
     * Process one batch of shield blocks through the Rust kit's
     * {@code sapling::sync::handle_blocks}: trial-decrypt outputs with the
     * viewing key, surface spent nullifiers, advance the commitment tree and
     * every existing note's witness.
     *
     * @param treeHex    hex-encoded commitment tree (wallet state before batch)
     * @param blocksJson {@code [{"height": H, "txs": ["<hex>", ...]}, ...]} —
     *                   one entry per block, txs are raw packets from the
     *                   shield stream (0x03/0x04 tag byte included)
     * @param extfvk     bech32 extended full viewing key
     * @param notesJson  JSON array of the kit's {@code SerializedNote} shape
     *                   (Jackson serializes jpivx's record identically)
     * @return the kit's {@code HandleBlocksResult} as JSON —
     *         {@code {commitment_tree, new_notes, updated_notes, nullifiers}}
     */
    public static String handleBlocks(String treeHex, String blocksJson,
                                      String extfvk, String notesJson) {
        requireAvailable();
        return nativeHandleBlocks(treeHex, blocksJson, extfvk, notesJson);
    }

    /**
     * Build and sign a shield transaction spending the wallet's notes,
     * through the Rust kit's {@code sapling::builder::create_shield_transaction}.
     *
     * <p>Note selection (non-memo notes first, ascending value), the exact
     * fee charged, and the change output are all decided by the kit — the
     * returned JSON reports what was spent: {@code {txhex, nullifiers,
     * amount, fee}}.
     *
     * @param walletJson       the full in-memory wallet, Jackson-serialized
     *                         (plaintext; shape is identical to the kit's
     *                         {@code WalletData} serde form)
     * @param toAddress        {@code ps1...} (shield) or {@code D...}
     *                         (transparent) destination
     * @param amountSat        amount in satoshi
     * @param memo             memo text ("" for none; shield destinations)
     * @param blockHeight      chain tip + 1 (expiry / anchor context)
     * @param spendParamsPath  path to {@code sapling-spend.params}
     *                         (SHA256-verified natively against the kit's pins)
     * @param outputParamsPath path to {@code sapling-output.params}
     * @return the kit's {@code TransactionResult} as JSON
     */
    public static String createShieldTransaction(String walletJson, String toAddress,
                                                 long amountSat, String memo, long blockHeight,
                                                 String spendParamsPath, String outputParamsPath) {
        requireAvailable();
        return nativeCreateShieldTransaction(walletJson, toAddress, amountSat, memo,
                blockHeight, spendParamsPath, outputParamsPath);
    }

    /**
     * Build and sign a <em>shielding</em> transaction — transparent UTXOs in,
     * shield output out — through the Rust kit's
     * {@code transparent::builder::create_shielding_transaction}.
     *
     * <p>The mirror image of {@link #createShieldTransaction}: the inputs are
     * the wallet's transparent UTXOs ({@code unspent_utxos} in {@code walletJson}),
     * the destination must be a {@code ps1...} address, and change goes back
     * as a transparent output. UTXO selection (largest first) and the fee are
     * decided by the kit.
     *
     * <p>Every input is signed with the key at {@code m/44'/119'/0'/0/0} —
     * the native side rejects UTXOs tagged with a non-zero
     * {@code hd_index}, and derives the signing seed from the wallet's own
     * mnemonic inside {@code walletJson}, so the seed and the UTXO set can
     * never disagree.
     *
     * @param walletJson       the kit's {@code WalletData} shape, carrying the
     *                         transparent UTXOs, the mnemonic, and the
     *                         commitment tree
     * @param toAddress        {@code ps1...} shield destination
     * @param amountSat        amount the shield recipient receives, in satoshi
     * @param blockHeight      chain tip (expiry / anchor context)
     * @param spendParamsPath  path to {@code sapling-spend.params}
     * @param outputParamsPath path to {@code sapling-output.params} (both
     *                         SHA256-verified on first use, then cached)
     * @return the kit's {@code TransparentTransactionResult} as JSON —
     *         {@code {txhex, spent, amount, fee}}
     */
    public static String createShieldingTransaction(String walletJson, String toAddress,
                                                    long amountSat, long blockHeight,
                                                    String spendParamsPath,
                                                    String outputParamsPath) {
        requireAvailable();
        return nativeCreateShieldingTransaction(walletJson, toAddress, amountSat,
                blockHeight, spendParamsPath, outputParamsPath);
    }

    /**
     * Quote the UTXO selection a shielding send would make — the exact
     * greedy pass and fee {@link #createShieldingTransaction} will be
     * charged, via the kit's pure {@code select_shielding_utxos}. No keys,
     * no params, no network.
     *
     * @param utxosJson JSON array of the kit's {@code SerializedUTXO} shape
     * @param amountSat target recipient amount
     * @return JSON {@code {inputs, total, fee}}
     * @throws IllegalArgumentException when the UTXOs cannot cover
     *         {@code amount + fee} (same wording as the builder)
     */
    public static String selectShieldingUtxos(String utxosJson, long amountSat) {
        requireAvailable();
        return nativeSelectShieldingUtxos(utxosJson, amountSat);
    }

    /**
     * Select which shield notes would be spent for an amount — the exact same
     * selection and fee the tx builder would charge. Pure (no params, no network).
     *
     * <p>Used to implement {@code --subtract-fee}: the fee depends on how many
     * notes get selected, so callers loop to a fixpoint
     * ({@code fee → sendAmount = budget − fee → re-select}) before building.
     *
     * @param notesJson      JSON array of the kit's {@code SerializedNote} shape
     * @param amountSat      target send amount (recipient-side)
     * @param transparentOuts transparent outputs in the tx (1 for a {@code D...}
     *                        destination, else 0)
     * @param saplingOuts    sapling outputs in the tx (typically 2: dest + change)
     * @return JSON {@code {indexes, fee, total}}
     */
    public static String selectShieldNotes(String notesJson, long amountSat,
                                           long transparentOuts, long saplingOuts) {
        requireAvailable();
        return nativeSelectShieldNotes(notesJson, amountSat, transparentOuts, saplingOuts);
    }

    // ---- native entry points (implemented in native/shield-jni/src/lib.rs) ----

    private static native String nativeExtfvk(byte[] bip39Seed);

    private static native String nativeDefaultShieldAddress(byte[] bip39Seed);

    private static native String[] nativeShieldAddressAt(String extfvk, long startIndex);

    private static native String nativeHandleBlocks(String treeHex, String blocksJson,
                                                    String extfvk, String notesJson);

    private static native String nativeCreateShieldTransaction(
            String walletJson, String toAddress, long amountSat, String memo,
            long blockHeight, String spendParamsPath, String outputParamsPath);

    private static native String nativeCreateShieldingTransaction(
            String walletJson, String toAddress, long amountSat,
            long blockHeight, String spendParamsPath, String outputParamsPath);

    private static native String nativeSelectShieldingUtxos(String utxosJson, long amountSat);

    private static native String nativeSelectShieldNotes(
            String notesJson, long amountSat, long transparentOuts, long saplingOuts);

    // ---------------------------------------------------------------------
    // Native library loading
    // ---------------------------------------------------------------------

    private static void loadNativeLibrary() throws IOException {
        String fromProperty = System.getProperty(LIB_PROPERTY);
        if (fromProperty != null && !fromProperty.isBlank()) {
            System.load(fromProperty);
            return;
        }
        String fromEnv = System.getenv(LIB_ENV);
        if (fromEnv != null && !fromEnv.isBlank()) {
            System.load(fromEnv);
            return;
        }
        loadBundled();
    }

    private static void loadBundled() throws IOException {
        String platform = platformDir();
        String fileName = libFileName();
        String resource = "/native/" + platform + "/" + fileName;
        try (InputStream in = ShieldKeys.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IOException("bundled native library not found at " + resource
                        + " (set -D" + LIB_PROPERTY + "= or " + LIB_ENV + ")");
            }
            byte[] bytes = in.readAllBytes();

            // Cache the extraction under ~/.pivx-wallet/native/, keyed by
            // CRC32 of the payload: repeated JVM launches reuse the same file
            // instead of littering the temp dir with one copy per process.
            CRC32 crc = new CRC32();
            crc.update(bytes);
            Path cacheDir = Path.of(System.getProperty("user.home"),
                    ".pivx-wallet", "native", platform);
            Files.createDirectories(cacheDir);
            Path cached = cacheDir.resolve(fileName + "." + Long.toHexString(crc.getValue()));
            if (!Files.exists(cached) || Files.size(cached) != bytes.length) {
                Path tmp = Files.createTempFile(cacheDir, fileName, ".tmp");
                Files.write(tmp, bytes);
                Files.move(tmp, cached,
                        StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            }
            cached.toFile().setReadable(true, true);
            cached.toFile().setExecutable(true, true);
            System.load(cached.toAbsolutePath().toString());
        }
    }

    /** Directory name used for the bundled resource, e.g. {@code macos-aarch64}. */
    static String platformDir() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        String arch = System.getProperty("os.arch", "").toLowerCase(Locale.ROOT);

        String osPart;
        if (os.contains("mac")) {
            osPart = "macos";
        } else if (os.contains("win")) {
            osPart = "windows";
        } else {
            osPart = "linux";
        }

        String archPart = switch (arch) {
            case "aarch64", "arm64" -> "aarch64";
            case "x86_64", "amd64" -> "x86_64";
            default -> arch;
        };
        return osPart + "-" + archPart;
    }

    private static String libFileName() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (os.contains("mac")) {
            return "lib" + LIB_BASE_NAME + ".dylib";
        }
        if (os.contains("win")) {
            return LIB_BASE_NAME + ".dll";
        }
        return "lib" + LIB_BASE_NAME + ".so";
    }
}
