package dev.jpivx.wallet.internal;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class MnemonicCode {
    public static final MnemonicCode INSTANCE = new MnemonicCode();
    private final List<String> wordList;
    /** word → 11-bit index lookup (O(1) instead of List.indexOf O(n)). */
    private final java.util.Map<String, Integer> wordIndex;

    private MnemonicCode() {
        wordList = new ArrayList<>();
        try (InputStream is = getClass().getResourceAsStream("/dev/jpivx/wallet/internal/english.txt")) {
            if (is == null) throw new IllegalStateException("BIP39 wordlist not found in resources");
            BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
            String line;
            while ((line = reader.readLine()) != null) {
                String w = line.trim();
                if (!w.isEmpty()) wordList.add(w);
            }
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Failed to load BIP39 wordlist", e);
        }
        if (wordList.size() != 2048)
            throw new IllegalStateException("BIP39 wordlist must have 2048 words, got: " + wordList.size());
        wordIndex = new java.util.HashMap<>(4096);
        for (int i = 0; i < wordList.size(); i++) {
            wordIndex.put(wordList.get(i), i);
        }
    }

    /**
     * Convert raw entropy bytes to a BIP39 mnemonic word list.
     *
     * @param entropy 16–32 bytes, length must be a multiple of 4
     */
    public List<String> toMnemonic(byte[] entropy) throws MnemonicException.MnemonicLengthException {
        if (entropy.length % 4 != 0 || entropy.length < 16 || entropy.length > 32) {
            throw new MnemonicException.MnemonicLengthException(
                    "Entropy length must be a multiple of 4 between 16 and 32 bytes, got: " + entropy.length);
        }
        try {
            byte[] hash = sha256(entropy);

            // Build bit array: ENT bits of entropy + CS checksum bits
            int cs = entropy.length * 8 / 32; // ENT/32
            int totalBits = entropy.length * 8 + cs;
            boolean[] bits = new boolean[totalBits];
            for (int i = 0; i < entropy.length * 8; i++) {
                bits[i] = (entropy[i / 8] & (1 << (7 - (i % 8)))) != 0;
            }
            for (int i = 0; i < cs; i++) {
                bits[entropy.length * 8 + i] = (hash[i / 8] & (1 << (7 - (i % 8)))) != 0;
            }

            // Map 11-bit groups to words
            List<String> words = new ArrayList<>();
            for (int i = 0; i < totalBits / 11; i++) {
                int index = 0;
                for (int j = 0; j < 11; j++) {
                    index = (index << 1) | (bits[i * 11 + j] ? 1 : 0);
                }
                words.add(wordList.get(index));
            }
            return words;
        } catch (Exception e) {
            throw new RuntimeException("toMnemonic failed", e);
        }
    }

    /**
     * Validate a mnemonic word list: checks word count, each word exists in the BIP39 wordlist,
     * and verifies the BIP39 SHA-256 checksum.
     */
    public void check(List<String> words) throws MnemonicException {
        int n = words.size();
        if (n % 3 != 0 || n < 12 || n > 24) {
            throw new MnemonicException.MnemonicLengthException(
                    "Word count must be a multiple of 3 between 12 and 24, got: " + n);
        }

        // Map words → 11-bit indices, checking each word exists
        int[] indices = new int[n];
        for (int i = 0; i < n; i++) {
            Integer idx = wordIndex.get(words.get(i));
            if (idx == null) throw new MnemonicException.MnemonicWordException("Unknown BIP39 word: " + words.get(i));
            indices[i] = idx;
        }

        // Expand to bit array (n × 11 bits total)
        int totalBits = n * 11;
        boolean[] bits = new boolean[totalBits];
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < 11; j++) {
                bits[i * 11 + j] = (indices[i] & (1 << (10 - j))) != 0;
            }
        }

        // Split: first ENT bits = entropy, last CS bits = checksum
        int cs = totalBits / 33;        // checksum bit count = ENT/32
        int entBits = totalBits - cs;   // entropy bit count

        // Reconstruct entropy bytes
        byte[] entropy = new byte[entBits / 8];
        for (int i = 0; i < entropy.length; i++) {
            for (int j = 0; j < 8; j++) {
                if (bits[i * 8 + j]) entropy[i] |= (byte) (1 << (7 - j));
            }
        }

        // Verify BIP39 checksum: first CS bits of SHA256(entropy) must equal the checksum bits
        byte[] hash = sha256(entropy);
        for (int i = 0; i < cs; i++) {
            boolean expected = (hash[i / 8] & (1 << (7 - (i % 8)))) != 0;
            if (bits[entBits + i] != expected) {
                throw new MnemonicException.MnemonicChecksumException("BIP39 checksum mismatch");
            }
        }
    }

    /**
     * Derive the 64-byte BIP39 seed from a mnemonic word list using PBKDF2-HMAC-SHA512.
     *
     * @param mnemonic   the word list
     * @param passphrase optional passphrase (use {@code ""} for none)
     * @return 64-byte seed
     */
    public static byte[] toSeed(List<String> mnemonic, String passphrase) {
        String pass = String.join(" ", mnemonic);
        String salt = "mnemonic" + (passphrase != null ? passphrase : "");
        try {
            PBEKeySpec spec = new PBEKeySpec(
                    pass.toCharArray(), salt.getBytes(StandardCharsets.UTF_8), 2048, 512);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            return skf.generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new RuntimeException("PBKDF2 seed derivation failed", e);
        }
    }

    private static byte[] sha256(byte[] input) {
        return ByteUtil.sha256(input);
    }

    // -------------------------------------------------------------------------
    // Exception hierarchy (mirrors org.bitcoinj.crypto.MnemonicException)
    // -------------------------------------------------------------------------

    public static class MnemonicException extends Exception {
        public MnemonicException(String msg) { super(msg); }

        public static class MnemonicLengthException extends MnemonicException {
            public MnemonicLengthException(String msg) { super(msg); }
        }
        public static class MnemonicWordException extends MnemonicException {
            public MnemonicWordException(String msg) { super(msg); }
        }
        public static class MnemonicChecksumException extends MnemonicException {
            public MnemonicChecksumException(String msg) { super(msg); }
        }
    }
}
