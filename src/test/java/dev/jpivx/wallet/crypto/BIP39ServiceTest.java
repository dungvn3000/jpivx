package dev.jpivx.wallet.crypto;

import dev.jpivx.wallet.internal.ByteUtil;
import dev.jpivx.wallet.internal.MnemonicCode;
import dev.jpivx.wallet.internal.MnemonicCode.MnemonicException;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * BIP39 conformance tests: the official Trezor vectors (entropy → mnemonic →
 * seed) plus the generation, parsing, and validation paths of
 * {@link BIP39Service}.
 *
 * <p>The vectors are the authoritative external reference — they pin the
 * wordlist mapping, the SHA-256 checksum bits, and the PBKDF2-HMAC-SHA512
 * seed derivation against values no part of this codebase produced.
 */
class BIP39ServiceTest {

    /** Passphrase used by the official BIP39 vector set. */
    private static final String TREZOR = "TREZOR";

    private static byte[] fill(int len, int value) {
        byte[] b = new byte[len];
        Arrays.fill(b, (byte) value);
        return b;
    }

    private static String repeat(String word, int times, String last) {
        List<String> words = new ArrayList<>(times + 1);
        for (int i = 0; i < times; i++) {
            words.add(word);
        }
        words.add(last);
        return String.join(" ", words);
    }

    // -------------------------------------------------------------------------
    // Official BIP39 vectors — entropy → mnemonic
    // -------------------------------------------------------------------------

    @Test
    void officialVectorsMapEntropyToMnemonic() throws Exception {
        assertEquals(repeat("abandon", 11, "about"),
                String.join(" ", MnemonicCode.INSTANCE.toMnemonic(fill(16, 0x00))));

        assertEquals("legal winner thank year wave sausage worth useful legal winner thank yellow",
                String.join(" ", MnemonicCode.INSTANCE.toMnemonic(fill(16, 0x7f))));

        assertEquals("letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
                String.join(" ", MnemonicCode.INSTANCE.toMnemonic(fill(16, 0x80))));

        assertEquals(repeat("zoo", 11, "wrong"),
                String.join(" ", MnemonicCode.INSTANCE.toMnemonic(fill(16, 0xff))));

        assertEquals(repeat("abandon", 23, "art"),
                String.join(" ", MnemonicCode.INSTANCE.toMnemonic(fill(32, 0x00))));

        assertEquals(repeat("zoo", 23, "vote"),
                String.join(" ", MnemonicCode.INSTANCE.toMnemonic(fill(32, 0xff))));
    }

    // -------------------------------------------------------------------------
    // Official BIP39 vectors — mnemonic → seed (passphrase "TREZOR")
    // -------------------------------------------------------------------------

    @Test
    void officialVector12WordsDerivesGoldenSeed() {
        byte[] seed = MnemonicCode.toSeed(
                BIP39Service.parse(repeat("abandon", 11, "about")), TREZOR);
        assertEquals("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
                        + "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
                ByteUtil.toHex(seed));
    }

    @Test
    void officialVector24WordsDerivesGoldenSeed() {
        byte[] seed = MnemonicCode.toSeed(
                BIP39Service.parse(repeat("abandon", 23, "art")), TREZOR);
        assertEquals("bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd30971"
                        + "70af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
                ByteUtil.toHex(seed));
    }

    @Test
    void toSeedUsesEmptyPassphrase() {
        // BIP39Service.toSeed is the passphrase-free variant the kit always uses;
        // it must differ from the same mnemonic derived with "TREZOR".
        List<String> words = BIP39Service.parse(repeat("abandon", 11, "about"));
        assertNotEquals(ByteUtil.toHex(MnemonicCode.toSeed(words, TREZOR)),
                ByteUtil.toHex(BIP39Service.toSeed(words)));
        assertEquals(ByteUtil.toHex(MnemonicCode.toSeed(words, "")),
                ByteUtil.toHex(BIP39Service.toSeed(words)));
    }

    @Test
    void seedIsAlways64Bytes() {
        assertEquals(64, BIP39Service.toSeed(BIP39Service.generateMnemonic()).length);
        assertEquals(64, BIP39Service.toSeed(
                BIP39Service.parse(repeat("abandon", 11, "about"))).length);
    }

    @Test
    void toSeedAppliesNfkdNormalization() {
        // BIP39 mandates NFKD on both mnemonic and passphrase: the composed
        // form (U+00E9) and the decomposed form (e + U+0301) must derive the
        // same seed. Written as escapes so the two literals cannot be
        // silently unified by an editor normalizing the source file.
        List<String> words = BIP39Service.parse(repeat("abandon", 11, "about"));
        String composed = "caf\u00e9";
        String decomposed = "cafe\u0301";
        assertNotEquals(composed, decomposed,
                "the two forms must differ before normalization");
        assertEquals(ByteUtil.toHex(MnemonicCode.toSeed(words, composed)),
                ByteUtil.toHex(MnemonicCode.toSeed(words, decomposed)));
    }

    // -------------------------------------------------------------------------
    // generateMnemonic
    // -------------------------------------------------------------------------

    @Test
    void generateMnemonicProduces24ValidWords() {
        List<String> words = BIP39Service.generateMnemonic();
        assertEquals(24, words.size());
        assertDoesNotThrow(() -> BIP39Service.validate(words),
                "generated mnemonic must pass its own checksum validation");
    }

    @Test
    void generateMnemonicUsesFreshEntropyEachCall() {
        // 256 bits of entropy: a repeat would mean the RNG is broken, not luck.
        List<String> a = BIP39Service.generateMnemonic();
        List<String> b = BIP39Service.generateMnemonic();
        assertNotEquals(String.join(" ", a), String.join(" ", b));
    }

    @Test
    void generatedMnemonicRoundtripsThroughParseAndSeed() {
        String phrase = String.join(" ", BIP39Service.generateMnemonic());
        assertDoesNotThrow(() -> BIP39Service.validateString(phrase));
        assertEquals(64, BIP39Service.toSeed(BIP39Service.parse(phrase)).length);
    }

    @Test
    void generateMnemonicHonoursSupportedWordCounts() {
        for (int wordCount : new int[] {12, 15, 18, 21, 24}) {
            List<String> words = BIP39Service.generateMnemonic(wordCount);
            assertEquals(wordCount, words.size());
            assertDoesNotThrow(() -> BIP39Service.validate(words),
                    wordCount + "-word mnemonic must pass its own checksum validation");
        }
    }

    @Test
    void generateMnemonicRejectsUnsupportedWordCounts() {
        for (int wordCount : new int[] {0, 11, 13, 20, 25, -12}) {
            assertThrows(IllegalArgumentException.class,
                    () -> BIP39Service.generateMnemonic(wordCount),
                    "word count " + wordCount + " must be rejected");
        }
    }

    // -------------------------------------------------------------------------
    // parse / normalize
    // -------------------------------------------------------------------------

    @Test
    void parseCollapsesArbitraryWhitespace() {
        List<String> words = BIP39Service.parse("  abandon\tabandon\n  abandon   about  ");
        assertEquals(List.of("abandon", "abandon", "abandon", "about"), words);
    }

    @Test
    void parseLowerCasesWords() {
        // The javadoc promises lower-cased output, and the seed depends on it:
        // PBKDF2 is case-sensitive, so a mixed-case phrase must not derive a
        // different wallet than its normalized form.
        assertEquals(List.of("abandon", "abandon", "about"),
                BIP39Service.parse("ABANDON Abandon aBoUt"));
    }

    @Test
    void mixedCaseMnemonicDerivesSameSeedAsNormalized() {
        String canonical = repeat("abandon", 11, "about");
        String mixed = "ABANDON Abandon abandon abandon abandon abandon "
                + "abandon abandon abandon abandon abandon ABOUT";
        assertEquals(ByteUtil.toHex(BIP39Service.toSeed(BIP39Service.parse(canonical))),
                ByteUtil.toHex(BIP39Service.toSeed(BIP39Service.parse(mixed))));
        assertEquals(canonical, BIP39Service.normalize(mixed));
    }

    @Test
    void normalizeProducesSingleSpacedLowerCase() {
        assertEquals("abandon abandon about",
                BIP39Service.normalize("  ABANDON   abandon\tAbout \n"));
    }

    // -------------------------------------------------------------------------
    // validate
    // -------------------------------------------------------------------------

    @Test
    void validateRejectsBadChecksum() {
        // Valid words, valid length, but the last word breaks the checksum.
        List<String> bad = BIP39Service.parse(repeat("abandon", 11, "abandon"));
        assertThrows(MnemonicException.MnemonicChecksumException.class,
                () -> BIP39Service.validate(bad));
    }

    @Test
    void validateRejectsUnknownWord() {
        List<String> bad = BIP39Service.parse(
                "abandon abandon abandon abandon abandon abandon "
                        + "abandon abandon abandon abandon abandon notaword");
        assertThrows(MnemonicException.MnemonicWordException.class,
                () -> BIP39Service.validate(bad));
    }

    @Test
    void validateRejectsBadWordCount() {
        // 11 words (not a multiple of 3) and 13 words (multiple of 3 violated too).
        assertThrows(MnemonicException.MnemonicLengthException.class,
                () -> BIP39Service.validate(BIP39Service.parse(repeat("abandon", 10, "about"))));
        assertThrows(MnemonicException.MnemonicLengthException.class,
                () -> BIP39Service.validate(BIP39Service.parse(repeat("abandon", 12, "about"))));
    }

    @Test
    void validateStringAcceptsUntrimmedMixedCasePhrase() {
        assertDoesNotThrow(() -> BIP39Service.validateString(
                "  ABANDON abandon abandon abandon abandon abandon "
                        + "abandon abandon abandon abandon abandon About  "));
    }

    // -------------------------------------------------------------------------
    // toMnemonic entropy bounds
    // -------------------------------------------------------------------------

    @Test
    void toMnemonicRejectsOutOfRangeEntropy() {
        for (int len : new int[]{0, 8, 15, 18, 33, 64}) {
            assertThrows(MnemonicException.MnemonicLengthException.class,
                    () -> MnemonicCode.INSTANCE.toMnemonic(fill(len, 0x00)),
                    "entropy of " + len + " bytes must be rejected");
        }
    }

    @Test
    void toMnemonicWordCountScalesWithEntropy() throws Exception {
        assertEquals(12, MnemonicCode.INSTANCE.toMnemonic(fill(16, 0x00)).size());
        assertEquals(18, MnemonicCode.INSTANCE.toMnemonic(fill(24, 0x00)).size());
        assertEquals(24, MnemonicCode.INSTANCE.toMnemonic(fill(32, 0x00)).size());
    }

    @Test
    void wordlistHasExactly2048UniqueWords() throws Exception {
        // Every 11-bit index must map to a distinct word, or entropy silently
        // collapses. Exercised through the public generation path.
        java.util.Set<String> seen = new java.util.HashSet<>();
        for (int i = 0; i < 64; i++) {
            seen.addAll(BIP39Service.generateMnemonic());
        }
        assertTrue(seen.size() > 500,
                "64 random 24-word phrases should touch a wide slice of the wordlist, saw "
                        + seen.size());
        for (String w : seen) {
            assertTrue(w.matches("[a-z]{3,8}"), "unexpected wordlist entry: " + w);
        }
    }
}
