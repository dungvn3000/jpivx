package dev.jpivx.wallet.internal;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

class ByteUtilTest {

    // -------------------------------------------------------------------------
    // Hex
    // -------------------------------------------------------------------------

    @Test
    void toHexLowercase() {
        byte[] input = new byte[]{(byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF};
        assertEquals("deadbeef", ByteUtil.toHex(input));
    }

    @Test
    void toHexEmpty() {
        assertEquals("", ByteUtil.toHex(new byte[0]));
    }

    @Test
    void fromHexLowercase() {
        assertArrayEquals(new byte[]{(byte) 0xca, (byte) 0xfe},
                ByteUtil.fromHex("cafe"));
    }

    @Test
    void fromHexUppercase() {
        // HexFormat.parseHex must accept uppercase too
        assertArrayEquals(new byte[]{(byte) 0xCA, (byte) 0xFE},
                ByteUtil.fromHex("CAFE"));
    }

    @Test
    void fromHexRoundTrip() {
        byte[] original = new byte[]{1, 2, 3, (byte) 0xff, (byte) 0x80};
        assertArrayEquals(original, ByteUtil.fromHex(ByteUtil.toHex(original)));
    }

    @Test
    void fromHexInvalidThrows() {
        assertThrows(IllegalArgumentException.class, () -> ByteUtil.fromHex("xyz"));
        assertThrows(IllegalArgumentException.class, () -> ByteUtil.fromHex("a")); // odd length
    }

    // -------------------------------------------------------------------------
    // SHA-256
    // -------------------------------------------------------------------------

    @Test
    void sha256KnownVector() {
        // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        byte[] result = ByteUtil.sha256(new byte[0]);
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                ByteUtil.toHex(result));
    }

    @Test
    void sha256dKnownVector() {
        // SHA256d("") = 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456
        byte[] result = ByteUtil.sha256d(new byte[0]);
        assertEquals("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456",
                ByteUtil.toHex(result));
    }

    @Test
    void sha256dIsDoubleNotSingle() {
        byte[] input = "hello".getBytes();
        assertFalse(java.util.Arrays.equals(ByteUtil.sha256(input), ByteUtil.sha256d(input)),
                "sha256d must differ from sha256");
    }

    // -------------------------------------------------------------------------
    // Little-endian writers
    // -------------------------------------------------------------------------

    @Test
    void writeLeU32KnownValue() {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        ByteUtil.writeLeU32(buf, 0x01020304);
        assertArrayEquals(new byte[]{0x04, 0x03, 0x02, 0x01}, buf.toByteArray());
    }

    @Test
    void writeLeU32MaxUint() {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        ByteUtil.writeLeU32(buf, 0xFFFFFFFF);
        assertArrayEquals(new byte[]{(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF},
                buf.toByteArray());
    }

    @Test
    void writeLeU64KnownValue() {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        ByteUtil.writeLeU64(buf, 0x0102030405060708L);
        assertArrayEquals(new byte[]{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01},
                buf.toByteArray());
    }

    @Test
    void leU32MatchesWriteLeU32() {
        int v = 0xDEADBEEF;
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        ByteUtil.writeLeU32(buf, v);
        assertArrayEquals(buf.toByteArray(), ByteUtil.leU32(v));
    }

    @Test
    void leU64MatchesWriteLeU64() {
        long v = 0xCAFEBABE12345678L;
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        ByteUtil.writeLeU64(buf, v);
        assertArrayEquals(buf.toByteArray(), ByteUtil.leU64(v));
    }

    // -------------------------------------------------------------------------
    // Byte-array manipulation
    // -------------------------------------------------------------------------

    @Test
    void reverseInPlace() {
        byte[] b = {1, 2, 3, 4, 5};
        ByteUtil.reverseInPlace(b);
        assertArrayEquals(new byte[]{5, 4, 3, 2, 1}, b);
    }

    @Test
    void reverseInPlaceSingleElement() {
        byte[] b = {42};
        ByteUtil.reverseInPlace(b);
        assertArrayEquals(new byte[]{42}, b);
    }

    @Test
    void reversedReturnsCopy() {
        byte[] original = {1, 2, 3};
        byte[] copy = ByteUtil.reversed(original);
        assertArrayEquals(new byte[]{3, 2, 1}, copy);
        assertArrayEquals(new byte[]{1, 2, 3}, original); // original unchanged
    }

    @Test
    void concat() {
        byte[] a = {1, 2};
        byte[] b = {3, 4, 5};
        byte[] c = {};
        assertArrayEquals(new byte[]{1, 2, 3, 4, 5}, ByteUtil.concat(a, b));
        assertArrayEquals(new byte[]{1, 2, 3, 4, 5}, ByteUtil.concat(a, b, c));
    }

    @Test
    void slice() {
        byte[] b = {0, 1, 2, 3, 4};
        assertArrayEquals(new byte[]{1, 2, 3}, ByteUtil.slice(b, 1, 3));
    }

    @Test
    void sliceOutOfBoundsThrows() {
        byte[] b = {0, 1, 2};
        assertThrows(IllegalArgumentException.class, () -> ByteUtil.slice(b, 2, 5));
        assertThrows(IllegalArgumentException.class, () -> ByteUtil.slice(b, -1, 1));
    }
}
