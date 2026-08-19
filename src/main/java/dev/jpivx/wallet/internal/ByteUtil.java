package dev.jpivx.wallet.internal;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Byte and hex utility methods for jpivx.
 *
 * <p>Provides a single, dependency-free home for:
 * <ul>
 *   <li>Hex encoding / decoding (Java 21 {@link HexFormat}, no BouncyCastle).</li>
 *   <li>SHA-256 / double-SHA-256 hashing.</li>
 *   <li>Little-endian integer serialisation for Bitcoin/PIVX transactions.</li>
 *   <li>Byte-array manipulation (reverse, concatenate).</li>
 * </ul>
 *
 * <p>All methods are null-safe on non-null inputs and throw
 * {@link IllegalArgumentException} for obviously invalid arguments.
 */
public final class ByteUtil {

    private static final HexFormat HEX = HexFormat.of();

    private ByteUtil() {
        throw new AssertionError("no instances");
    }

    // =========================================================================
    // Hex
    // =========================================================================

    /**
     * Encode {@code bytes} as a lowercase hex string (e.g. {@code "0xab"} → {@code "ab"}).
     *
     * @param bytes source bytes; must not be null
     * @return lowercase hex string, empty string for empty input
     */
    public static String toHex(byte[] bytes) {
        return HEX.formatHex(bytes);
    }

    /**
     * Decode a lowercase or uppercase hex string to bytes.
     *
     * @param hex hex string (must have even length); must not be null
     * @return decoded bytes
     * @throws IllegalArgumentException if the string has odd length or invalid chars
     */
    public static byte[] fromHex(String hex) {
        try {
            return HEX.parseHex(hex);
        } catch (IllegalArgumentException e) {
            // Re-throw with clearer message
            throw new IllegalArgumentException("Invalid hex string: " + hex, e);
        }
    }

    // =========================================================================
    // SHA-256
    // =========================================================================

    /**
     * Single SHA-256 of {@code input}.
     *
     * @param input source bytes; must not be null
     * @return 32-byte digest
     */
    public static byte[] sha256(byte[] input) {
        return newSha256().digest(input);
    }

    /**
     * Double SHA-256 of {@code input} (SHA256(SHA256(input))).
     * Used throughout Bitcoin/PIVX for tx hashing, address checksums, etc.
     *
     * @param input source bytes; must not be null
     * @return 32-byte digest
     */
    public static byte[] sha256d(byte[] input) {
        MessageDigest md = newSha256();
        byte[] first = md.digest(input);   // SHA256(input), also resets md
        return md.digest(first);           // SHA256(SHA256(input))
    }

    private static MessageDigest newSha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    // =========================================================================
    // Little-endian integer writers
    // =========================================================================

    /**
     * Write a 32-bit unsigned integer in little-endian byte order to {@code buf}.
     *
     * @param buf output stream; must not be null
     * @param v   value (treated as unsigned 32-bit)
     */
    public static void writeLeU32(ByteArrayOutputStream buf, int v) {
        buf.write(v         & 0xff);
        buf.write((v >>>  8) & 0xff);
        buf.write((v >>> 16) & 0xff);
        buf.write((v >>> 24) & 0xff);
    }

    /**
     * Write a 64-bit integer in little-endian byte order to {@code buf}.
     *
     * @param buf output stream; must not be null
     * @param v   value
     */
    public static void writeLeU64(ByteArrayOutputStream buf, long v) {
        for (int i = 0; i < 8; i++) {
            buf.write((int) ((v >>> (i * 8)) & 0xff));
        }
    }

    /**
     * Encode a 32-bit unsigned integer as 4 little-endian bytes.
     *
     * @param v value (treated as unsigned 32-bit)
     * @return 4-byte array
     */
    public static byte[] leU32(int v) {
        return new byte[]{
            (byte)  v,
            (byte) (v >>>  8),
            (byte) (v >>> 16),
            (byte) (v >>> 24)
        };
    }

    /**
     * Encode a 64-bit integer as 8 little-endian bytes.
     *
     * @param v value
     * @return 8-byte array
     */
    public static byte[] leU64(long v) {
        byte[] b = new byte[8];
        for (int i = 0; i < 8; i++) {
            b[i] = (byte) (v >>> (i * 8));
        }
        return b;
    }

    // =========================================================================
    // Byte-array manipulation
    // =========================================================================

    /**
     * Reverse {@code b} in-place.
     *
     * @param b array to reverse; must not be null
     */
    public static void reverseInPlace(byte[] b) {
        for (int i = 0, j = b.length - 1; i < j; i++, j--) {
            byte t = b[i];
            b[i]  = b[j];
            b[j]  = t;
        }
    }

    /**
     * Return a new array containing the bytes of {@code b} in reverse order.
     *
     * @param b source array; must not be null
     * @return reversed copy
     */
    public static byte[] reversed(byte[] b) {
        byte[] copy = b.clone();
        reverseInPlace(copy);
        return copy;
    }

    /**
     * Concatenate two or more byte arrays into a single new array.
     *
     * @param arrays one or more byte arrays; must not be null
     * @return concatenated result
     */
    public static byte[] concat(byte[]... arrays) {
        int len = 0;
        for (byte[] a : arrays) len += a.length;
        byte[] result = new byte[len];
        int pos = 0;
        for (byte[] a : arrays) {
            System.arraycopy(a, 0, result, pos, a.length);
            pos += a.length;
        }
        return result;
    }

    /**
     * Return a copy of {@code b} with {@code length} bytes starting at {@code offset}.
     *
     * @param b      source array
     * @param offset start index (inclusive)
     * @param length number of bytes
     * @return copy of the slice
     * @throws IllegalArgumentException if the range is out of bounds
     */
    public static byte[] slice(byte[] b, int offset, int length) {
        if (offset < 0 || length < 0 || offset + length > b.length) {
            throw new IllegalArgumentException(
                    "slice out of bounds: offset=" + offset + " length=" + length
                    + " array.length=" + b.length);
        }
        byte[] result = new byte[length];
        System.arraycopy(b, offset, result, 0, length);
        return result;
    }
}
