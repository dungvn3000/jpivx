package dev.jpivx.wallet.shield;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;

import java.util.List;

import dev.jpivx.wallet.crypto.ShieldKeys;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JNI shield-send bridge test that needs NO proving params: a wallet with no
 * notes trips the bridge's early-fail before parameter loading. Crucially it
 * also proves the full <b>Jackson → serde_json → kit WalletData</b> roundtrip
 * — a field mismatch would fail deserialization BEFORE the balance error.
 */
class ShieldSendJniTest {

    private static final String TEST_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    static boolean shieldAvailable() {
        return ShieldKeys.isAvailable();
    }

    /**
     * Build a minimal wallet JSON in the kit's WalletData shape via the
     * production facade (empty notes, empty tree).
     */
    static String buildWalletJson(String mnemonic, int birthdayHeight) throws Exception {
        ShieldState state = new ShieldState(birthdayHeight, "", List.of());
        return ShieldSendService.buildWalletJson(mnemonic, birthdayHeight, state);
    }

    @Test
    @EnabledIf("shieldAvailable")
    void walletJsonRoundtripsAndEmptyNotesFailFast() throws Exception {
        String walletJson = buildWalletJson(TEST_MNEMONIC, 5_000_000);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
                ShieldKeys.createShieldTransaction(
                        walletJson,
                        "ps124f3dxhmtygh72cu8f05t94yey59at3armnk44uctjwdqf9uk2grnth3h5uszmqzzeev7kcr7rn",
                        100_000L, "", 5_000_001L,
                        "/nonexistent/sapling-spend.params",
                        "/nonexistent/sapling-output.params"));

        // "insufficient" (not a file/serde error) proves both the JSON
        // roundtrip AND the pre-parameter early-fail.
        assertTrue(ex.getMessage() != null && ex.getMessage().contains("insufficient"),
                "unexpected error: " + ex.getMessage());
    }

    @Test
    @EnabledIf("shieldAvailable")
    void rejectsOutOfRangeBlockHeight() throws Exception {
        String walletJson = buildWalletJson(TEST_MNEMONIC, 5_000_000);
        assertThrows(IllegalArgumentException.class, () ->
                ShieldKeys.createShieldTransaction(
                        walletJson, "ps1x", 100L, "", -1L, "/n/a", "/n/a"));
    }
}
