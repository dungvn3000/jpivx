package dev.jpivx.wallet.internal;

import java.util.Arrays;

public class Sha256Hash {
    private final byte[] bytes;

    private Sha256Hash(byte[] bytes) {
        if (bytes.length != 32) {
            throw new IllegalArgumentException("Hash must be 32 bytes");
        }
        this.bytes = bytes;
    }

    public static Sha256Hash wrap(byte[] rawHashBytes) {
        return new Sha256Hash(rawHashBytes);
    }

    public byte[] getBytes() {
        return bytes;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Sha256Hash that = (Sha256Hash) o;
        return Arrays.equals(bytes, that.bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }
}
