package dev.jpivx.wallet.core;

/**
 * PIVX mainnet chain constants — single source of truth for chain-specific values.
 *
 * <p>Mirrors {@code src/params.rs} of the Rust {@code pivx-wallet-kit}. Keep the
 * byte values and identifiers byte-for-byte identical so wallets produced here
 * interoperate with wallets produced by the Rust kit.
 */
public final class PivxParams {

    /** Satoshis per PIV (8 decimal places). */
    public static final long COIN = 100_000_000L;

    /** BIP44 coin type for PIVX mainnet (NOT Bitcoin's 0). */
    public static final int PIVX_COIN_TYPE = 119;

    /** Base58Check version byte for PIVX transparent pubkey addresses (produces {@code D...}). */
    public static final byte PIVX_PUBKEY_PREFIX = 30;

    /** SIGHASH_ALL flag byte appended to legacy (v1) transparent signature preimages. */
    public static final int SIGHASH_ALL = 1;

    /** Expected SHA256 of the Sapling output parameters (Groth16 proving key). */
    public static final String OUTPUT_PARAMS_SHA256 =
            "2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4";

    /** Expected SHA256 of the Sapling spend parameters (Groth16 proving key). */
    public static final String SPEND_PARAMS_SHA256 =
            "8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13";

    /** PIVX Core magic prefix for {@code signmessage}/{@code verifymessage}. */
    public static final String PIVX_MSG_MAGIC = "DarkNet Signed Message:\n";

    private PivxParams() {
        throw new AssertionError("no instances");
    }
}
