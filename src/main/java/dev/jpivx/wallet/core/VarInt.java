package dev.jpivx.wallet.core;

import java.io.ByteArrayOutputStream;

/**
 * Bitcoin-style variable-length integer (CompactSize) serialization.
 *
 * <p>Mirrors {@code src/transparent/tx.rs::write_varint} of the Rust
 * {@code pivx-wallet-kit}. Used by the v1 P2PKH transaction builder to
 * encode input/output counts and script-lengths.
 *
 * <pre>
 * &lt; 0xfd          → 1 byte:  the value
 * &le; 0xffff        → 3 bytes: 0xfd, value LE u16
 * &le; 0xffff_ffff   → 5 bytes: 0xfe, value LE u32
 * otherwise        → 9 bytes: 0xff, value LE u64
 * </pre>
 */
public final class VarInt {

    private VarInt() {
        throw new AssertionError("no instances");
    }

    /**
     * Write a Bitcoin-style compact-size varint to the buffer.
     *
     * @param buf the buffer to append to
     * @param val the value to encode, interpreted as an <em>unsigned</em>
     *            64-bit integer (all 64 bits are significant; matches the
     *            Rust {@code u64} parameter type)
     */
    public static void write(ByteArrayOutputStream buf, long val) {
        // Treat val as unsigned 64-bit. The 9-byte band triggers when the
        // value exceeds 0xffff_ffff, i.e. when the high 32 bits are nonzero
        // OR the value is exactly in the u64 range above 0xffffffff.
        if (Long.compareUnsigned(val, 0xfdL) < 0) {
            buf.write((int) val);
        } else if (Long.compareUnsigned(val, 0xffffL) <= 0) {
            buf.write(0xfd);
            buf.write((int) (val & 0xff));
            buf.write((int) ((val >>> 8) & 0xff));
        } else if (Long.compareUnsigned(val, 0xffff_ffffL) <= 0) {
            buf.write(0xfe);
            buf.write((int) (val & 0xff));
            buf.write((int) ((val >>> 8) & 0xff));
            buf.write((int) ((val >>> 16) & 0xff));
            buf.write((int) ((val >>> 24) & 0xff));
        } else {
            buf.write(0xff);
            buf.write((int) (val & 0xff));
            buf.write((int) ((val >>> 8) & 0xff));
            buf.write((int) ((val >>> 16) & 0xff));
            buf.write((int) ((val >>> 24) & 0xff));
            buf.write((int) ((val >>> 32) & 0xff));
            buf.write((int) ((val >>> 40) & 0xff));
            buf.write((int) ((val >>> 48) & 0xff));
            buf.write((int) ((val >>> 56) & 0xff));
        }
    }
}
