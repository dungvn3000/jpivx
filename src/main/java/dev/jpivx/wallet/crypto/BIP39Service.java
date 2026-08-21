package dev.jpivx.wallet.crypto;

import dev.jpivx.wallet.internal.MnemonicCode;
import dev.jpivx.wallet.internal.MnemonicCode.MnemonicException;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

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

    /** Default word count when none is given (matches Rust {@code create_new_wallet}). */
    public static final int DEFAULT_WORD_COUNT = 24;

    /** Word counts accepted by {@link #generateMnemonic(int)}. */
    public static final List<Integer> SUPPORTED_WORD_COUNTS =
            Collections.unmodifiableList(Arrays.asList(12, 15, 18, 21, 24));

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
     */
    public static List<String> generateMnemonic() {
        return generateMnemonic(DEFAULT_WORD_COUNT);
    }

    /**
     * Generate a fresh mnemonic of the requested length using a cryptographically strong RNG.
     *
     * @param wordCount one of {@code 12}, {@code 15}, {@code 18}, {@code 21}, {@code 24}
     * @return the mnemonic word list
     * @throws IllegalArgumentException if {@code wordCount} is not a supported length
     */
    public static List<String> generateMnemonic(int wordCount) {
        int entropyBytes = entropyBytesFor(wordCount);
        try {
            byte[] entropy = new byte[entropyBytes];
            try {
                SecureRandom.getInstanceStrong().nextBytes(entropy);
            } catch (NoSuchAlgorithmException e) {
                new SecureRandom().nextBytes(entropy);
            }
            return MnemonicCode.INSTANCE.toMnemonic(entropy);
        } catch (MnemonicException.MnemonicLengthException e) {
            throw new IllegalStateException(entropyBytes + "-byte entropy is always valid BIP39", e);
        }
    }

    /** Entropy length in bytes for a supported word count: {@code wordCount * 11 / 8} rounded to ENT. */
    private static int entropyBytesFor(int wordCount) {
        switch (wordCount) {
            case 12: return 16;
            case 15: return 20;
            case 18: return 24;
            case 21: return 28;
            case 24: return ENTROPY_BYTES_24_WORDS;
            default:
                throw new IllegalArgumentException(
                        "Unsupported word count: " + wordCount + " (supported: " + SUPPORTED_WORD_COUNTS + ")");
        }
    }

    /**
     * Validate a mnemonic phrase against the BIP39 wordlist + checksum.
     *
     * @param mnemonic the word list
     * @throws MnemonicException on invalid length, unknown word, or checksum failure
     * @throws IOException if the bundled wordlist cannot be loaded (first use)
     */
    public static void validate(List<String> mnemonic) throws MnemonicException, IOException {
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
                words.add(p.toLowerCase(Locale.ROOT));
            }
        }
        return words;
    }

    /**
     * Validate a raw mnemonic string (parse + check).
     */
    public static void validateString(String mnemonic) throws MnemonicException, IOException {
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
