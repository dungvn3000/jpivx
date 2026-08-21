package dev.jpivx.wallet.crypto;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Port of {@code derive_transparent_address_from_mnemonic} and
 * {@code decode_transparent_address_roundtrips_to_script} from
 * {@code tests/integration.rs}, plus golden-vector assertions captured from the
 * Rust kit ({@code cargo test print_signature_for_cross_verify -- --nocapture}).
 */
class TransparentKeysTest {

    /** BIP39 test vector — same mnemonic used across the Rust kit's tests. */
    static final String TEST_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /**
     * Golden vector from Rust: the transparent address derived at
     * {@code m/44'/119'/0'/0/0} from {@link #TEST_MNEMONIC} is
     * {@code DPo9TNvPwy2ZfmVM3CRCxbBvh6NojguWXJ}. Captured via
     * {@code print_signature_for_cross_verify}.
     */
    static final String EXPECTED_ADDRESS = "DPo9TNvPwy2ZfmVM3CRCxbBvh6NojguWXJ";

    @Test
    void deriveTransparentAddressFromMnemonic() {
        String addr = TransparentKeys.getTransparentAddress(TEST_MNEMONIC);
        assertTrue(addr.startsWith("D"),
                "PIVX transparent address should start with 'D', got: " + addr);
        assertEquals(34, addr.length(),
                "PIVX address should be 34 chars, got: " + addr.length());
        // Deterministic — derive twice, expect identical.
        String addr2 = TransparentKeys.getTransparentAddress(TEST_MNEMONIC);
        assertEquals(addr, addr2);
    }

    @Test
    void transparentAddressMatchesRustGoldenVector() {
        assertEquals(EXPECTED_ADDRESS, TransparentKeys.getTransparentAddress(TEST_MNEMONIC));
    }

    @Test
    void mixedCaseMnemonicDerivesSameAddress() {
        // parse() lower-cases words, so casing must not change the seed —
        // otherwise the stored (normalized) mnemonic wouldn't reproduce the wallet.
        String mixed = TEST_MNEMONIC.substring(0, 1).toUpperCase(Locale.ROOT)
                + TEST_MNEMONIC.substring(1);
        assertEquals(EXPECTED_ADDRESS, TransparentKeys.getTransparentAddress(mixed));
    }

    @Test
    void transparentKeyTripleHasCorrectShape() {
        byte[] seed = BIP39Service.toSeed(BIP39Service.parse(TEST_MNEMONIC));
        TransparentKeys.TransparentKey key =
                TransparentKeys.transparentKeyFromBip39Seed(seed, 0, 0);

        assertEquals(EXPECTED_ADDRESS, key.address());
        assertEquals(33, key.pubkey().length, "compressed pubkey must be 33 bytes");
        assertEquals(32, key.privkey().length, "privkey must be 32 bytes");
        // Re-derive address from the pubkey independently — must match.
        assertEquals(EXPECTED_ADDRESS, PivxAddress.pubkeyToPivxAddress(key.pubkey()));
    }

    @Test
    void deriveCustomHdIndex() {
        // Index 5 — exercised by the Rust test raw_transparent_from_utxos_signs_with_custom_hd_index.
        byte[] seed = BIP39Service.toSeed(BIP39Service.parse(TEST_MNEMONIC));
        TransparentKeys.TransparentKey key =
                TransparentKeys.transparentKeyFromBip39Seed(seed, 0, 5);

        assertNotNull(key.address());
        assertTrue(key.address().startsWith("D"));
        assertEquals(34, key.address().length());
        // Different index → different address from the default.
        assertNotEquals(EXPECTED_ADDRESS, key.address());
    }

    @Test
    void deriveChangeBranch() {
        byte[] seed = BIP39Service.toSeed(BIP39Service.parse(TEST_MNEMONIC));
        TransparentKeys.TransparentKey external =
                TransparentKeys.transparentKeyFromBip39Seed(seed, 0, 0);
        TransparentKeys.TransparentKey internal =
                TransparentKeys.transparentKeyFromBip39Seed(seed, 1, 0);
        assertNotEquals(external.address(), internal.address(), "external (change=0) and internal (change=1) branches must differ");
    }

    @Test
    void zeroizeWipesPrivkey() {
        byte[] priv = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
        TransparentKeys.zeroize(priv);
        assertArrayEquals(new byte[8], priv);
    }

}
