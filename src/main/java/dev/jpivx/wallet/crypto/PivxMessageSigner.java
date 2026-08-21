package dev.jpivx.wallet.crypto;

import dev.jpivx.wallet.internal.ECKey;
import dev.jpivx.wallet.internal.Sha256Hash;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

import dev.jpivx.wallet.core.PivxParams;

/**
 * PIVX Core-compatible {@code signmessage} / {@code verifymessage}.
 *
 * <p>Mirrors {@code src/messages.rs} of the Rust {@code pivx-wallet-kit}. Wire format:
 * <ol>
 *   <li>Hash the magic-prefixed, compact-size-length-prefixed message.</li>
 *   <li>Sign the double-SHA256 digest with secp256k1 ECDSA (RFC6979 deterministic).</li>
 *   <li>Encode as a 65-byte blob: header byte {@code 27 + recid + 4} (compressed marker)
 *       followed by the 64-byte compact (r‖s) signature.</li>
 *   <li>Standard base64-encode the blob.</li>
 * </ol>
 *
 * <p>Signatures produced here verify against PIVX Core's {@code verifymessage} RPC
 * and vice-versa. Recovery uses a hand-rolled secp256k1 public-key recovery
 * (BouncyCastle has no built-in ECDSA recovery id), brute-forcing the 4 candidate
 * recovery ids to find the one whose recovered pubkey matches the signer.
 */
public final class PivxMessageSigner {

    private PivxMessageSigner() {
        throw new AssertionError("no instances");
    }

    /**
     * Sign {@code message} with the given 32-byte private key.
     *
     * @param privkey 32-byte secp256k1 private key
     * @param message the message text
     * @return base64 signature byte-compatible with PIVX Core's {@code verifymessage}
     * @throws IllegalArgumentException if the privkey is not 32 bytes
     */
    public static String signMessage(byte[] privkey, String message) {
        if (privkey.length != 32) {
            throw new IllegalArgumentException("privkey must be exactly 32 bytes; got " + privkey.length);
        }
        ECKey ecKey = ECKey.fromPrivate(privkey, true); // compressed
        byte[] hash = messageHash(message);
        // sign() already returns a canonicalised (Low-S) signature.
        ECKey.ECDSASignature sig = ecKey.sign(Sha256Hash.wrap(hash));
        byte[] expectedPubkey = ecKey.getPubKey(); // 33 bytes compressed

        // Brute-force the recovery id (0..3): the recid whose recovered pubkey
        // matches the signer's actual compressed pubkey is the right one.
        int recid = -1;
        for (int candidate = 0; candidate < 4; candidate++) {
            byte[] recovered = recoverPubKey(hash, sig.r, sig.s, candidate);
            if (recovered != null && Arrays.equals(recovered, expectedPubkey)) {
                recid = candidate;
                break;
            }
        }
        if (recid < 0) {
            throw new IllegalStateException("Could not find recovery id — internal ECDSA error");
        }

        byte header = (byte) (27 + recid + 4); // +4 marks compressed pubkey (PIVX Core always uses compressed)
        byte[] full = new byte[65];
        full[0] = header;
        encodeCompactR(sig.r, full, 1);
        encodeCompactR(sig.s, full, 33);
        return Base64.getEncoder().encodeToString(full);
    }

    /**
     * Verify that {@code signatureB64} is a valid PIVX Core-format signature of
     * {@code message} by the keypair owning {@code address}.
     *
     * @param address       the {@code D...} transparent address
     * @param message       the message text
     * @param signatureB64  base64 signature (65 bytes decoded)
     * @return {@code true} only if the recovered public key derives to exactly {@code address}
     * @throws IllegalArgumentException on malformed signature (bad base64, wrong length,
     *         header out of range, or unrecoverable signature)
     */
    public static boolean verifyMessage(String address, String message, String signatureB64) {
        byte[] sigBytes;
        try {
            sigBytes = Base64.getDecoder().decode(signatureB64);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Bad base64: " + e.getMessage(), e);
        }
        if (sigBytes.length != 65) {
            throw new IllegalArgumentException("Signature must be exactly 65 bytes; got " + sigBytes.length);
        }
        int header = sigBytes[0] & 0xff;
        if (header < 27 || header > 34) {
            throw new IllegalArgumentException("Bad header byte: " + header);
        }
        boolean compressed = header >= 31;
        int recid = compressed ? (header - 31) : (header - 27);

        BigInteger r = new BigInteger(1, Arrays.copyOfRange(sigBytes, 1, 33));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(sigBytes, 33, 65));
        byte[] hash = messageHash(message);

        byte[] recovered = recoverPubKey(hash, r, s, recid);
        if (recovered == null) {
            throw new IllegalArgumentException("Could not recover pubkey from signature");
        }
        // PIVX Core compressed/uncompressed selection — the compressed flag
        // determines which pubkey form is compared. We re-encode if needed.
        byte[] pubkeyBytes = compressed
                ? recovered
                : decompressPubKey(recovered);
        if (pubkeyBytes == null) {
            throw new IllegalArgumentException("Could not decompress recovered pubkey");
        }
        String recoveredAddr = PivxAddress.pubkeyToPivxAddress(pubkeyBytes);
        return recoveredAddr.equals(address);
    }

    // ---- message hashing (matches PIVX Core wire format) ----

    /**
     * Compute the 32-byte digest a PIVX Core signed-message signature is over:
     * double-SHA256 of {@code [compact_size(magic) || magic || compact_size(msg) || msg]}.
     */
    static byte[] messageHash(String message) {
        byte[] magic = PivxParams.PIVX_MSG_MAGIC.getBytes(StandardCharsets.UTF_8);
        byte[] msg = message.getBytes(StandardCharsets.UTF_8);
        ByteBuffer buf = ByteBuffer.allocate(magic.length + msg.length + 18)
                .order(ByteOrder.LITTLE_ENDIAN); // Bitcoin compact-size is LE
        writeCompactSize(buf, magic.length);
        buf.put(magic);
        writeCompactSize(buf, msg.length);
        buf.put(msg);
        buf.flip();
        byte[] preimage = new byte[buf.remaining()];
        buf.get(preimage);
        return PivxAddress.doubleSha256(preimage);
    }

    private static void writeCompactSize(ByteBuffer buf, long n) {
        if (n < 0xfd) {
            buf.put((byte) n);
        } else if (n <= 0xffff) {
            buf.put((byte) 0xfd);
            buf.putShort((short) n);
        } else if (n <= 0xffff_ffffL) {
            buf.put((byte) 0xfe);
            buf.putInt((int) n);
        } else {
            buf.put((byte) 0xff);
            buf.putLong(n);
        }
    }

    // ---- ECDSA pubkey recovery (secp256k1) ----

    private static byte[] recoverPubKey(byte[] messageHash, BigInteger r, BigInteger s, int recid) {
        ECDomainParameters params = ECKey.CURVE;
        BigInteger n = params.getN();
        // libsecp256k1 rejects r,s outside [1, n-1]; r=0 would also make
        // r.modInverse(n) below throw an uncaught ArithmeticException.
        if (r.signum() <= 0 || r.compareTo(n) >= 0 || s.signum() <= 0 || s.compareTo(n) >= 0) {
            return null;
        }
        org.bouncycastle.math.ec.ECCurve curve = params.getCurve();
        BigInteger p = curve.getField().getCharacteristic();

        // x = r + (recid >> 1) * n
        BigInteger x = r;
        if ((recid & 2) != 0) {
            x = x.add(n);
        }
        if (x.compareTo(p) >= 0) {
            return null; // x outside the field
        }

        // y^2 = x^3 + 7 (secp256k1: a=0, b=7)
        BigInteger y2 = x.pow(3).add(BigInteger.valueOf(7)).mod(p);
        // y = y2^((p+1)/4) mod p (valid because p ≡ 3 (mod 4) for secp256k1)
        BigInteger exp = p.add(BigInteger.ONE).shiftRight(2);
        BigInteger y = y2.modPow(exp, p);
        if (!y.multiply(y).mod(p).equals(y2)) {
            return null; // no square root → invalid point
        }
        // recid & 1 → odd y parity
        boolean wantOdd = (recid & 1) == 1;
        if (y.testBit(0) != wantOdd) {
            y = p.subtract(y);
        }

        ECPoint R;
        try {
            R = curve.createPoint(x, y).normalize();
        } catch (IllegalArgumentException e) {
            return null;
        }

        BigInteger e = new BigInteger(1, messageHash).mod(n);
        BigInteger rInv = r.modInverse(n);
        ECPoint G = params.getG();

        // Q = r^-1 * (s*R - e*G)
        ECPoint sR = R.multiply(s).normalize();
        ECPoint eG = G.multiply(e).normalize();
        ECPoint Q = sR.subtract(eG).multiply(rInv).normalize();

        if (Q.isInfinity()) {
            return null;
        }
        return Q.getEncoded(true); // compressed 33 bytes
    }

    private static byte[] decompressPubKey(byte[] compressed) {
        try {
            ECPoint p = ECKey.CURVE.getCurve().decodePoint(compressed);
            return p.getEncoded(false); // 65 bytes uncompressed
        } catch (Exception e) {
            return null;
        }
    }

    private static void encodeCompactR(BigInteger v, byte[] out, int off) {
        byte[] b = v.toByteArray();
        if (b.length == 32) {
            System.arraycopy(b, 0, out, off, 32);
        } else if (b.length == 33 && b[0] == 0) {
            System.arraycopy(b, 1, out, off, 32); // strip sign byte
        } else if (b.length < 32) {
            Arrays.fill(out, off, off + (32 - b.length), (byte) 0);
            System.arraycopy(b, 0, out, off + (32 - b.length), b.length);
        } else {
            throw new IllegalStateException("scalar too large for 32 bytes: " + b.length);
        }
    }
}
