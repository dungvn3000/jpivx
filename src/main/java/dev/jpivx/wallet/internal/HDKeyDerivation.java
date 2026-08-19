package dev.jpivx.wallet.internal;

import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class HDKeyDerivation {

    private static final byte[] BITCOIN_SEED = "Bitcoin seed".getBytes(StandardCharsets.UTF_8);

    /**
     * Create the BIP32 master private key from a BIP39 seed.
     *
     * @param seed 64-byte BIP39 seed
     * @return master {@link DeterministicKey}
     */
    public static DeterministicKey createMasterPrivateKey(byte[] seed) {
        byte[] i = hmacSha512(BITCOIN_SEED, seed);
        byte[] il = Arrays.copyOfRange(i, 0, 32);
        byte[] ir = Arrays.copyOfRange(i, 32, 64);

        BigInteger priv = new BigInteger(1, il);
        // BIP32: if master key bytes >= N this seed is invalid (astronomically rare)
        if (priv.compareTo(ECKey.CURVE.getN()) >= 0 || priv.equals(BigInteger.ZERO)) {
            throw new IllegalArgumentException("BIP32: master seed produces an invalid key — try a different seed");
        }
        ECPoint pub = new FixedPointCombMultiplier().multiply(ECKey.CURVE.getG(), priv);
        return new DeterministicKey(List.of(), ir, pub, priv, null);
    }

    /**
     * Derive a BIP32 child key.
     *
     * <p>Throws {@link IllegalStateException} if attempting a hardened derivation from a
     * public-key-only key (no private component). Throws {@link IllegalArgumentException}
     * if the derived child key is invalid per BIP32 spec (callers should skip to the next
     * index in that case; probability ≈ 1 / 2¹²⁷).
     *
     * @param parent      parent key
     * @param childNumber child index (hardened or normal)
     * @return derived child {@link DeterministicKey}
     */
    public static DeterministicKey deriveChildKey(DeterministicKey parent, ChildNumber childNumber) {
        if (childNumber.isHardened() && parent.getPrivKey() == null) {
            throw new IllegalStateException(
                    "Cannot derive hardened child key from a public-key-only DeterministicKey");
        }

        byte[] data = new byte[37];
        if (childNumber.isHardened()) {
            // Hardened: HMAC-SHA512(chainCode, 0x00 || privKey || index)
            System.arraycopy(parent.getPrivKeyBytes33(), 0, data, 0, 33);
        } else {
            // Normal: HMAC-SHA512(chainCode, compressedPubKey || index)
            byte[] pubKey = parent.getPubKey();
            System.arraycopy(pubKey, 0, data, 0, pubKey.length);
        }
        int childNum = childNumber.getI();
        data[33] = (byte) (childNum >>> 24);
        data[34] = (byte) (childNum >>> 16);
        data[35] = (byte) (childNum >>> 8);
        data[36] = (byte) childNum;

        byte[] i = hmacSha512(parent.getChainCode(), data);
        byte[] il = Arrays.copyOfRange(i, 0, 32);
        byte[] ir = Arrays.copyOfRange(i, 32, 64);

        BigInteger ilInt = new BigInteger(1, il);
        BigInteger n = ECKey.CURVE.getN();

        // BIP32 spec: if il >= N this child index is invalid — caller should try next index
        if (ilInt.compareTo(n) >= 0) {
            throw new IllegalArgumentException(
                    "BIP32: il >= N for child " + childNumber + " — skip to next index");
        }

        BigInteger priv = ilInt.add(parent.getPrivKey()).mod(n);

        // BIP32 spec: if child private key is 0 the index is invalid
        if (priv.equals(BigInteger.ZERO)) {
            throw new IllegalArgumentException(
                    "BIP32: child private key is zero for child " + childNumber + " — skip to next index");
        }

        ECPoint pub = new FixedPointCombMultiplier().multiply(ECKey.CURVE.getG(), priv);
        List<ChildNumber> newPath = new ArrayList<>(parent.getPath());
        newPath.add(childNumber);
        return new DeterministicKey(newPath, ir, pub, priv, parent);
    }

    // -------------------------------------------------------------------------

    private static byte[] hmacSha512(byte[] key, byte[] data) {
        HMac hmac = new HMac(new SHA512Digest());
        hmac.init(new KeyParameter(key));
        hmac.update(data, 0, data.length);
        byte[] out = new byte[64];
        hmac.doFinal(out, 0);
        return out;
    }
}
