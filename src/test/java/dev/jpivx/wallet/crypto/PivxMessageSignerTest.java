package dev.jpivx.wallet.crypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Port of {@code roundtrip_compressed} and {@code malformed_signatures_error}
 * from {@code src/messages.rs}, plus a golden-vector cross-verification against
 * the Rust kit's signature for the same mnemonic + message
 * ({@code cargo test print_signature_for_cross_verify -- --nocapture}).
 */
class PivxMessageSignerTest {

    static final String TEST_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    // Golden vector captured from the Rust kit (print_signature_for_cross_verify):
    //   ADDRESS:   DPo9TNvPwy2ZfmVM3CRCxbBvh6NojguWXJ
    //   MESSAGE:   PIVX-Wallet-Kit signing test 2026-04-25
    //   SIGNATURE: H99Lj8PyrSfV5ZzW30tmhJclCvcU67mD5djIbkv9Oao6D168EEKP/trF2nQLiy3LDYjbivlsym/LbrPYQTSVZp8=
    static final String GOLDEN_ADDRESS = "DPo9TNvPwy2ZfmVM3CRCxbBvh6NojguWXJ";
    static final String GOLDEN_MESSAGE = "PIVX-Wallet-Kit signing test 2026-04-25";
    static final String GOLDEN_SIGNATURE =
            "H99Lj8PyrSfV5ZzW30tmhJclCvcU67mD5djIbkv9Oao6D168EEKP/trF2nQLiy3LDYjbivlsym/LbrPYQTSVZp8=";

    private static byte[] derivePrivKey() {
        byte[] seed = BIP39Service.toSeed(BIP39Service.parse(TEST_MNEMONIC));
        TransparentKeys.TransparentKey key =
                TransparentKeys.transparentKeyFromBip39Seed(seed, 0, 0);
        return key.privkey();
    }

    @Test
    void roundtripCompressed() {
        byte[] privkey = derivePrivKey();
        String address = TransparentKeys.getTransparentAddress(TEST_MNEMONIC);

        String message = "Hello, PIVX!";
        String sig = PivxMessageSigner.signMessage(privkey, message);
        assertTrue(PivxMessageSigner.verifyMessage(address, message, sig));

        // Wrong message must fail.
        assertFalse(PivxMessageSigner.verifyMessage(address, "Goodbye", sig));

        // Wrong address must fail.
        String otherAddr = "DBnaqM7apSWDqRVU9Ppi3eR2bUzYGX6gxF";
        assertFalse(PivxMessageSigner.verifyMessage(otherAddr, message, sig));
    }

    @Test
    void signatureMatchesRustGoldenVector() {
        // The signature must be byte-identical to the one produced by the Rust
        // kit for the same mnemonic + message — both libraries use RFC6979
        // deterministic nonces, so r and s are deterministic and the recovery
        // id is uniquely determined by the pubkey.
        byte[] privkey = derivePrivKey();
        String sig = PivxMessageSigner.signMessage(privkey, GOLDEN_MESSAGE);
        org.junit.jupiter.api.Assertions.assertEquals(GOLDEN_SIGNATURE, sig,
                "Java signature must match the Rust kit's golden vector");

        // And the golden signature must verify against the golden address.
        assertTrue(PivxMessageSigner.verifyMessage(GOLDEN_ADDRESS, GOLDEN_MESSAGE, GOLDEN_SIGNATURE),
                "Rust-produced signature must verify under the Java verifier");
    }

    @Test
    void malformedSignaturesError() {
        String addr = "DPo9TNvPwy2ZfmVM3CRCxbBvh6NojguWXJ";
        // Empty
        assertThrows(IllegalArgumentException.class,
                () -> PivxMessageSigner.verifyMessage(addr, "msg", ""));
        // Wrong length (decoded to 32 bytes)
        String tooShort = java.util.Base64.getEncoder().encodeToString(new byte[32]);
        assertThrows(IllegalArgumentException.class,
                () -> PivxMessageSigner.verifyMessage(addr, "msg", tooShort));
        // Bad header byte (decoded to 65 bytes but header out of range)
        byte[] bad = new byte[65];
        bad[0] = 99;
        String badB64 = java.util.Base64.getEncoder().encodeToString(bad);
        assertThrows(IllegalArgumentException.class,
                () -> PivxMessageSigner.verifyMessage(addr, "msg", badB64));
    }

    @Test
    void signMessageRejectsBadPrivkeyLength() {
        assertThrows(IllegalArgumentException.class,
                () -> PivxMessageSigner.signMessage(new byte[31], "msg"));
        assertThrows(IllegalArgumentException.class,
                () -> PivxMessageSigner.signMessage(new byte[33], "msg"));
    }

}
