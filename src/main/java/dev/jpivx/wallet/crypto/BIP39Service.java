package dev.jpivx.wallet.crypto;

import dev.jpivx.wallet.internal.MnemonicCode;
import dev.jpivx.wallet.internal.MnemonicCode.MnemonicException;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * BIP39 mnemonic phrase generation, validation, and seed derivation.
 *
 * <p>Mirrors the BIP39 usage in {@code src/keys.rs} / {@code src/wallet.rs} of
 * the Rust {@code pivx-wallet-kit}: passphrase is always {@code ""}, and the
 * 64-byte seed is produced via PBKDF2-HMAC-SHA512 (salt {@code "mnemonic"+mnemonic},
 * 2048 iterations) — identical to {@link MnemonicCode#toSeed}.
 *
 * <p>Wordlist is the bundled English list from bitcoinj (no network access).
 */
public final class BIP39Service {

    /** Entropy length for a 24-word mnemonic (matches Rust {@code create_new_wallet}). */
    public static final int ENTROPY_BYTES_24_WORDS = 32;

    private BIP39Service() {
        throw new AssertionError("no instances");
    }

    /**
     * Derive the 64-byte BIP39 seed from a mnemonic (passphrase = {@code ""}).
     *
     * @param mnemonic the word list
     * @return 64-byte seed
     */
    public static byte[] toSeed(List<String> mnemonic) {
        return MnemonicCode.toSeed(mnemonic, "");
    }

    /**
     * Generate a fresh 24-word mnemonic using a cryptographically strong RNG.
     *
     * @return the mnemonic word list (24 words)
     * @throws MnemonicException.MnemonicLengthException never in practice (32 bytes is valid)
     */
    public static List<String> generateMnemonic() {
        try {
            byte[] entropy = new byte[ENTROPY_BYTES_24_WORDS];
            try {
                SecureRandom.getInstanceStrong().nextBytes(entropy);
            } catch (java.security.NoSuchAlgorithmException e) {
                new SecureRandom().nextBytes(entropy);
            }
            return MnemonicCode.INSTANCE.toMnemonic(entropy);
        } catch (MnemonicException.MnemonicLengthException e) {
            throw new IllegalStateException("32-byte entropy is always valid BIP39", e);
        }
    }

    /**
     * Validate a mnemonic phrase against the BIP39 wordlist + checksum.
     *
     * @param mnemonic the word list
     * @throws MnemonicException on invalid length, unknown word, or checksum failure
     * @throws java.io.IOException if the bundled wordlist cannot be loaded (first use)
     */
    public static void validate(List<String> mnemonic) throws MnemonicException, java.io.IOException {
        MnemonicCode.INSTANCE.check(mnemonic);
    }

    /**
     * Split a whitespace-separated mnemonic string into a normalised word list.
     *
     * @param mnemonic the raw phrase, e.g. {@code "abandon abandon ... about"}
     * @return the word list, trimmed and lower-cased
     */
    public static List<String> parse(String mnemonic) {
        String[] parts = mnemonic.trim().split("\\s+");
        List<String> words = new ArrayList<>(parts.length);
        for (String p : parts) {
            if (!p.isEmpty()) {
                words.add(p.toLowerCase(java.util.Locale.ROOT));
            }
        }
        return words;
    }

    /**
     * Validate a raw mnemonic string (parse + check).
     */
    public static void validateString(String mnemonic) throws MnemonicException, java.io.IOException {
        List<String> words = parse(mnemonic);
        validate(words);
    }

    /**
     * Normalise a mnemonic string into a single-space-separated, lower-cased form
     * (matches Rust {@code Mnemonic::parse_normalized}).
     */
    public static String normalize(String mnemonic) {
        return String.join(" ", parse(mnemonic));
    }
}
