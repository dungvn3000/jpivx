package dev.jpivx.wallet.internal;

import org.bouncycastle.math.ec.ECPoint;
import java.math.BigInteger;
import java.util.List;

public class DeterministicKey {
    private final List<ChildNumber> path;
    private final byte[] chainCode;
    private final ECPoint pub;
    private final BigInteger priv;
    private final DeterministicKey parent;

    public DeterministicKey(List<ChildNumber> path, byte[] chainCode, ECPoint pub,
                            BigInteger priv, DeterministicKey parent) {
        this.path = path;
        this.chainCode = chainCode;
        this.pub = pub;
        this.priv = priv;
        this.parent = parent;
    }

    /**
     * Return the private key as a 33-byte zero-padded big-endian array
     * (0x00 prefix byte followed by 32 key bytes), as used in BIP32 hardened
     * child derivation.
     *
     * @throws IllegalStateException if this key has no private component
     */
    public byte[] getPrivKeyBytes33() {
        if (priv == null) {
            throw new IllegalStateException(
                    "Cannot get private key bytes: this DeterministicKey is public-key-only");
        }
        byte[] bytes33 = new byte[33]; // zero-filled; bytes33[0] == 0x00
        byte[] privBytes = priv.toByteArray();
        // toByteArray() may have a leading 0x00 sign byte or be shorter than 32 bytes
        int srcOffset = privBytes.length > 32 ? privBytes.length - 32 : 0;
        int dstOffset = 33 - Math.min(privBytes.length, 32);
        System.arraycopy(privBytes, srcOffset, bytes33, dstOffset, Math.min(privBytes.length, 32));
        return bytes33;
    }

    public ECPoint getPubKeyPoint() {
        return pub;
    }

    /** Returns the 33-byte compressed public key. */
    public byte[] getPubKey() {
        return pub.getEncoded(true);
    }

    public byte[] getChainCode() {
        return chainCode;
    }

    /**
     * Returns the private key scalar, or {@code null} if this is a public-key-only key.
     */
    public BigInteger getPrivKey() {
        return priv;
    }

    public List<ChildNumber> getPath() {
        return path;
    }
}
