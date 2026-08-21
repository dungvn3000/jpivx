package dev.jpivx.wallet.crypto;

import dev.jpivx.wallet.internal.ChildNumber;
import dev.jpivx.wallet.internal.DeterministicKey;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

/**
 * Transparent (BIP32/BIP44) key derivation for PIVX.
 *
 * <p>Wraps {@link BIP32Service} + {@link PivxAddress} to reproduce the Rust
 * {@code keys::transparent_key_from_bip39_seed} triple
 * {@code (address, compressed_pubkey[33], privkey[32])} at path
 * {@code m/44'/119'/0'/{change}/{index}}.
 */
public final class TransparentKeys {

    private TransparentKeys() {
        throw new AssertionError("no instances");
    }

    /** Result of transparent key derivation. */
    public record TransparentKey(String address, byte[] pubkey, byte[] privkey) {
        public TransparentKey {
            pubkey = pubkey.clone();
            privkey = privkey.clone();
        }
    }

    /**
     * Derive a BIP44 transparent key triple at {@code m/44'/119'/0'/{change}/{index}}.
     *
     * @param bip39Seed 64-byte BIP39 seed (full, from {@link BIP39Service#toSeed})
     * @param change    0 = external/receive, 1 = internal/change
     * @param index     address index within the change branch
     * @return {@link TransparentKey} with {@code D...} address, 33-byte compressed pubkey, 32-byte privkey
     */
    public static TransparentKey transparentKeyFromBip39Seed(byte[] bip39Seed, int change, int index) {
        List<ChildNumber> path = BIP32Service.pivxTransparentPath(change, index);
        DeterministicKey key = BIP32Service.deriveFromSeed(bip39Seed, path);

        byte[] pubkey = key.getPubKey(); // 33 bytes compressed
        if (pubkey.length != 33) {
            throw new IllegalStateException("Expected 33-byte compressed pubkey, got " + pubkey.length);
        }
        byte[] privkey = bigIntTo32Bytes(key.getPrivKey());
        String address = PivxAddress.pubkeyToPivxAddress(pubkey);
        return new TransparentKey(address, pubkey, privkey);
    }

    /**
     * Derive the default transparent address ({@code m/44'/119'/0'/0/0}) from a
     * mnemonic string. Convenience wrapper.
     *
     * @param mnemonic BIP39 mnemonic phrase
     * @return {@code D...} address
     */
    public static String getTransparentAddress(String mnemonic) {
        List<String> words = BIP39Service.parse(mnemonic);
        byte[] seed = BIP39Service.toSeed(words);
        return transparentKeyFromBip39Seed(seed, 0, 0).address();
    }

    /**
     * Zeroise a private key byte array in place. Best-effort defence; Java gives
     * no hard guarantee the GC won't have copied it, but this matches the
     * Rust kit's {@code Zeroizing} intent.
     */
    public static void zeroize(byte[] privkey) {
        if (privkey != null) {
            Arrays.fill(privkey, (byte) 0);
        }
    }

    static byte[] bigIntTo32Bytes(BigInteger v) {
        byte[] b = v.toByteArray();
        if (b.length == 32) {
            return b;
        }
        if (b.length == 33 && b[0] == 0) {
            return Arrays.copyOfRange(b, 1, 33); // strip sign byte
        }
        if (b.length > 32) {
            throw new IllegalStateException("value too large for 32 bytes: " + b.length);
        }
        byte[] out = new byte[32];
        System.arraycopy(b, 0, out, 32 - b.length, b.length); // left-pad
        return out;
    }
}
