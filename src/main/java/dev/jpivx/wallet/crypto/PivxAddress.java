package dev.jpivx.wallet.crypto;

import org.bouncycastle.crypto.digests.RIPEMD160Digest;

import java.nio.ByteBuffer;
import java.util.Arrays;

import dev.jpivx.wallet.internal.Base58;
import dev.jpivx.wallet.internal.ByteUtil;
import dev.jpivx.wallet.core.PivxParams;

/**
 * PIVX transparent address (base58check, {@code D...}) encoding and decoding.
 *
 * <p>Mirrors the transparent half of {@code src/keys.rs}:
 * <ul>
 *   <li>{@link #pubkeyToPivxAddress}: SHA256 → RIPEMD160 → base58check with prefix 30.</li>
 *   <li>{@link #addressToP2pkhScript}: decode base58check → {@code OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG}.</li>
 * </ul>
 */
public final class PivxAddress {

    /** Length of a PIVX base58check transparent address string. */
    public static final int ADDRESS_LENGTH = 34;

    private PivxAddress() {
        throw new AssertionError("no instances");
    }

    /** Outcome of {@link #validate(String)}: what kind of address this is. */
    public enum AddressType {
        /** Valid transparent address (base58check; pubkey-hash or script-hash prefix). */
        TRANSPARENT,
        /** Valid shield address ({@code ps1...}, full bech32 + jubjub point check). */
        SHIELD,
        /** Not a valid PIVX mainnet address of either kind. */
        INVALID
    }

    /**
     * Fully validate a PIVX address of either kind, through the Rust kit's
     * {@code keys::decode_generic_address} — the same decode every transaction
     * builder performs, so a {@code TRANSPARENT}/{@code SHIELD} verdict here
     * means the builders will accept it. Shield addresses get the complete
     * check a pure-Java validator cannot do (bech32 checksum, HRP, payload
     * length, jubjub point decompression).
     *
     * <p>Note the kit counts both the pubkey-hash ({@code D...}) and
     * script-hash transparent prefixes as {@code TRANSPARENT}; jpivx's own
     * transaction builders pay P2PKH only —
     * {@link #isValidTransparent(String)} is the pure-Java check for exactly
     * the addresses {@link #addressToP2pkhScript(String)} accepts, and needs
     * no native library.
     *
     * @param address the address to validate (null/blank is {@code INVALID})
     * @return the address kind, or {@link AddressType#INVALID}
     * @throws IllegalStateException if the native shield library is unavailable
     */
    public static AddressType validate(String address) {
        if (address == null || address.isBlank()) {
            return AddressType.INVALID;
        }
        return switch (ShieldKeys.validateAddress(address)) {
            case "shield" -> AddressType.SHIELD;
            case "transparent" -> AddressType.TRANSPARENT;
            default -> AddressType.INVALID;
        };
    }

    /**
     * True when {@code address} is a valid PIVX mainnet P2PKH transparent
     * address ({@code D...}) — base58check checksum, length, and version byte.
     * Pure Java: works without the native shield library, and matches exactly
     * what {@link #addressToP2pkhScript(String)} accepts.
     */
    public static boolean isValidTransparent(String address) {
        if (address == null || address.isBlank()) {
            return false;
        }
        try {
            addressToHash160(address);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Convert a compressed (or uncompressed) public key to a PIVX transparent
     * address ({@code D...}).
     *
     * @param pubkey 33-byte compressed (or 65-byte uncompressed) secp256k1 public key
     * @return base58check address
     */
    public static String pubkeyToPivxAddress(byte[] pubkey) {
        byte[] sha = sha256(pubkey);
        byte[] ripe = ripemd160(sha);
        return Base58.encodeChecked(PivxParams.PIVX_PUBKEY_PREFIX & 0xff, ripe);
    }

    /**
     * Decode a base58 transparent PIVX address to its P2PKH scriptPubKey.
     *
     * @param address the base58check address ({@code D...})
     * @return 25-byte script: {@code OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG}
     * @throws IllegalArgumentException if the address is malformed (bad length or
     *         checksum) or its version byte is not the PIVX mainnet pubkey prefix
     */
    public static byte[] addressToP2pkhScript(String address) {
        byte[] pkh = addressToHash160(address);
        byte[] script = new byte[25];
        script[0] = (byte) 0x76; // OP_DUP
        script[1] = (byte) 0xa9; // OP_HASH160
        script[2] = (byte) 0x14; // push 20 bytes
        System.arraycopy(pkh, 0, script, 3, 20);
        script[23] = (byte) 0x88; // OP_EQUALVERIFY
        script[24] = (byte) 0xac; // OP_CHECKSIG
        return script;
    }

    /**
     * Decode a base58 transparent PIVX address to its 20-byte hash160.
     *
     * @param address the base58check address
     * @return 20-byte hash160
     * @throws IllegalArgumentException if malformed or not a PIVX mainnet pubkey address
     */
    public static byte[] addressToHash160(String address) {
        byte[] decoded = Base58.decodeChecked(address);
        if (decoded.length != 21) {
            throw new IllegalArgumentException("Invalid address length: " + decoded.length);
        }
        int version = decoded[0] & 0xff;
        if (version != (PivxParams.PIVX_PUBKEY_PREFIX & 0xff)) {
            throw new IllegalArgumentException("Not a PIVX mainnet transparent address"
                    + " (version byte " + version + ", expected "
                    + (PivxParams.PIVX_PUBKEY_PREFIX & 0xff) + "): " + address);
        }
        return Arrays.copyOfRange(decoded, 1, 21);
    }

    /**
     * Reconstruct a PIVX address from a 20-byte hash160 + the PIVX prefix byte.
     */
    public static String hash160ToAddress(byte[] hash160) {
        if (hash160.length != 20) {
            throw new IllegalArgumentException("hash160 must be 20 bytes: " + hash160.length);
        }
        return Base58.encodeChecked(PivxParams.PIVX_PUBKEY_PREFIX & 0xff, hash160);
    }

    static byte[] sha256(byte[] input) {
        return ByteUtil.sha256(input);
    }

    /** Double SHA-256 (Bitcoin "Hash256"). */
    public static byte[] doubleSha256(byte[] input) {
        return ByteUtil.sha256d(input);
    }

    static byte[] ripemd160(byte[] input) {
        RIPEMD160Digest digest = new RIPEMD160Digest();
        digest.update(input, 0, input.length);
        byte[] out = new byte[20];
        digest.doFinal(out, 0);
        return out;
    }

}
