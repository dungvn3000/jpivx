package dev.jpivx.wallet.internal;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;

import java.math.BigInteger;

public class ECKey {

    // secp256k1 curve parameters — loaded once at class initialisation
    public static final ECDomainParameters CURVE;
    public static final BigInteger HALF_CURVE_ORDER;

    static {
        org.bouncycastle.asn1.x9.X9ECParameters params = CustomNamedCurves.getByName("secp256k1");
        CURVE = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
        HALF_CURVE_ORDER = params.getN().shiftRight(1);
    }

    private final BigInteger privKey;
    private final ECPoint pubKey;
    private final boolean compressed;
    /**
     * Pre-computed BouncyCastle parameter object — avoids allocating it on every {@link #sign} call.
     * {@code null} for public-key-only instances (e.g. recovered from a signature).
     */
    private final ECPrivateKeyParameters privKeyParams;

    private ECKey(BigInteger privKey, ECPoint pubKey, boolean compressed) {
        this.privKey = privKey;
        this.pubKey = pubKey;
        this.compressed = compressed;
        this.privKeyParams = (privKey != null) ? new ECPrivateKeyParameters(privKey, CURVE) : null;
    }

    /** Create an {@code ECKey} from raw private-key bytes. */
    public static ECKey fromPrivate(byte[] privKeyBytes, boolean compressed) {
        return fromPrivate(new BigInteger(1, privKeyBytes), compressed);
    }

    /** Create an {@code ECKey} from a private-key scalar. */
    public static ECKey fromPrivate(BigInteger privKey, boolean compressed) {
        ECPoint pubKey = new FixedPointCombMultiplier().multiply(CURVE.getG(), privKey);
        return new ECKey(privKey, pubKey, compressed);
    }

    /**
     * Sign {@code hash} with RFC 6979 deterministic ECDSA and return a canonicalised (Low-S) signature.
     *
     * @throws IllegalStateException if this key has no private component
     */
    public ECDSASignature sign(Sha256Hash hash) {
        if (privKeyParams == null) {
            throw new IllegalStateException("Cannot sign: this ECKey has no private component");
        }
        // ECDSASigner is not thread-safe — create a fresh instance per call (lightweight)
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        signer.init(true, privKeyParams);
        BigInteger[] components = signer.generateSignature(hash.getBytes());
        return new ECDSASignature(components[0], components[1]).toCanonicalised();
    }

    /** Returns the compressed (33-byte) or uncompressed (65-byte) public key encoding. */
    public byte[] getPubKey() {
        return pubKey.getEncoded(compressed);
    }

    /**
     * Recover a public key from a signature and the hash that was signed.
     *
     * @param recId      0 or 1 (recovery id)
     * @param sig        the ECDSA signature
     * @param hash       the hash that was signed
     * @param compressed whether to return a compressed key
     * @return the recovered key, or {@code null} if recovery fails for this {@code recId}
     */
    public static ECKey recoverFromSignature(int recId, ECDSASignature sig, Sha256Hash hash, boolean compressed) {
        BigInteger n = CURVE.getN();
        BigInteger i = BigInteger.valueOf((long) recId / 2);
        BigInteger x = sig.r.add(i.multiply(n));

        BigInteger prime = ((org.bouncycastle.math.ec.ECCurve.Fp) CURVE.getCurve()).getQ();
        if (x.compareTo(prime) >= 0) return null;

        ECPoint R = decompressKey(x, (recId & 1) == 1);
        if (!R.multiply(n).isInfinity()) return null;

        BigInteger e = new BigInteger(1, hash.getBytes());
        BigInteger eInv = BigInteger.ZERO.subtract(e).mod(n);
        BigInteger rInv = sig.r.modInverse(n);
        BigInteger srInv = rInv.multiply(sig.s).mod(n);
        BigInteger eInvrInv = rInv.multiply(eInv).mod(n);

        ECPoint q = R.multiply(srInv).add(CURVE.getG().multiply(eInvrInv));
        return new ECKey(null, q, compressed);
    }

    /**
     * Decompress a secp256k1 point from its x-coordinate and the y-parity bit.
     * Uses the already-initialised {@link #CURVE} to avoid repeated curve lookups.
     */
    private static ECPoint decompressKey(BigInteger xBN, boolean yBit) {
        byte[] compEnc = new byte[33];
        compEnc[0] = (byte) (yBit ? 0x03 : 0x02);
        byte[] xEnc = xBN.toByteArray();
        // xEnc may be 33 bytes (with leading 0x00 sign byte) or fewer than 32 bytes
        int srcOffset = xEnc.length > 32 ? xEnc.length - 32 : 0;
        int dstOffset = 1 + (32 - Math.min(xEnc.length, 32));
        System.arraycopy(xEnc, srcOffset, compEnc, dstOffset, Math.min(xEnc.length, 32));
        return CURVE.getCurve().decodePoint(compEnc);
    }

    // =========================================================================
    // ECDSASignature
    // =========================================================================

    public static class ECDSASignature {
        public final BigInteger r;
        public final BigInteger s;

        public ECDSASignature(BigInteger r, BigInteger s) {
            this.r = r;
            this.s = s;
        }

        /**
         * Enforce BIP62 Low-S: if {@code s > n/2}, replace with {@code n - s}.
         */
        public ECDSASignature toCanonicalised() {
            if (s.compareTo(HALF_CURVE_ORDER) > 0) {
                return new ECDSASignature(r, CURVE.getN().subtract(s));
            }
            return this;
        }

        /** Encode as DER (standard Bitcoin wire format). */
        public byte[] encodeToDER() {
            try {
                ASN1EncodableVector v = new ASN1EncodableVector();
                v.add(new ASN1Integer(r));
                v.add(new ASN1Integer(s));
                return new DERSequence(v).getEncoded(ASN1Encoding.DER);
            } catch (Exception e) {
                throw new RuntimeException("DER encoding failed", e);
            }
        }
    }
}
