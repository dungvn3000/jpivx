package dev.jpivx.wallet.core;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * CompactSize varint encoding tests — mirrors {@code write_varint} behaviour
 * exercised indirectly by the Rust transparent-builder tests. Covers all four
 * encoding bands. Values are interpreted as unsigned 64-bit (matching the
 * Rust {@code u64} parameter type).
 */
class VarIntTest {

    private static byte[] encode(long v) {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        VarInt.write(buf, v);
        return buf.toByteArray();
    }

    @Test
    void singleByteBand() {
        for (int v = 0; v < 0xfd; v++) {
            assertArrayEquals(new byte[]{(byte) v}, encode(v));
        }
    }

    @Test
    void threeByteBandBoundary() {
        // 0xfd exactly: 0xfd 0xfd 0x00
        assertArrayEquals(new byte[]{(byte) 0xfd, (byte) 0xfd, 0x00}, encode(0xfd));
        // 0xffff: 0xfd 0xff 0xff
        assertArrayEquals(new byte[]{(byte) 0xfd, (byte) 0xff, (byte) 0xff}, encode(0xffff));
    }

    @Test
    void fiveByteBandBoundary() {
        // 0x10000: 0xfe 0x00 0x00 0x01 0x00
        assertArrayEquals(new byte[]{(byte) 0xfe, 0x00, 0x00, 0x01, 0x00}, encode(0x10000L));
        // 0xffffffff: 0xfe 0xff 0xff 0xff 0xff
        assertArrayEquals(new byte[]{(byte) 0xfe, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff}, encode(0xffffffffL));
    }

    @Test
    void nineByteBand() {
        // 0x1_0000_0000: 0xff 0x00 0x00 0x00 0x00 0x01 0x00 0x00 0x00
        assertArrayEquals(
                new byte[]{(byte) 0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00},
                encode(0x1_0000_0000L));
        // u64::MAX
        assertArrayEquals(
                new byte[]{(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff},
                encode(0xffff_ffff_ffff_ffffL));
    }

    @Test
    void rejectsNegative() {
        // VarInt now treats its input as unsigned u64 (matching Rust), so the
        // bit pattern 0xffff_ffff_ffff_ffff (= -1 signed) is a valid 9-byte
        // encoding. This test pins the encoding to guard against regressions
        // if someone re-introduces a signed < 0 guard.
        assertArrayEquals(
                new byte[]{(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff},
                encode(-1L));
    }

    @Test
    void matchesRustWireFormatForCommonCounts() {
        // These are the counts that actually appear in v1 P2PKH txs built by
        // create_raw_transparent_transaction: 1 input, 1 or 2 outputs.
        assertArrayEquals(new byte[]{0x01}, encode(1));
        assertArrayEquals(new byte[]{0x02}, encode(2));
        // scriptSig length varint in the 0xfd..0xffff band is unlikely in practice
        // but a 0xfd payload (253 bytes) is exactly the boundary.
        assertArrayEquals(new byte[]{(byte) 0xfd, (byte) 0xfd, 0x00}, encode(253));
    }
}
