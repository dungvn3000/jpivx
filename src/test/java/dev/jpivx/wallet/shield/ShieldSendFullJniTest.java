package dev.jpivx.wallet.shield;

import com.grack.nanojson.JsonParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;

import java.util.HexFormat;
import java.util.List;

import dev.jpivx.wallet.crypto.PivxAddress;
import dev.jpivx.wallet.crypto.ShieldKeys;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Full Groth16 path through the real JNI bridge: builds and SIGNS a real
 * shield→shield transaction using a self-owned crafted note pinned from the
 * Rust kit's `build_real_shield_tx_offline` test (same mnemonic, same note,
 * same witness → same nullifier and fee).
 *
 * <p>Gated on the Sapling params being cached locally
 * ({@code ~/.pivx-wallet/params}) — on machines without them the suite skips.
 */
class ShieldSendFullJniTest {

    private static final String TEST_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    // Pinned from shield-jni's build_real_shield_tx_offline (self-owned note
    // for the test mnemonic, witnessed at position 0 on a fresh tree).
    private static final String NOTE_JSON =
            "{\"recipient\":[85,83,22,154,251,89,17,127,43,28,58,95,69,150,164,201,40,94,174,61,30,231,106,215,152,92,156,208,36,188,178,144,57,174,241,189,57,1,108,2,22,114,207],\"value\":10000000,\"rseed\":[202,218,35,229,114,124,47,70,73,72,153,81,125,56,67,233,82,48,194,70,127,160,38,79,173,78,187,142,61,87,60,2]}";
    private static final String WITNESS_HEX =
            "0159f0769bb5e071919fc1511956a1c258b2e703b60311f670791a5b4d1c6a203600000000";
    private static final String EXPECTED_NULLIFIER =
            "e5b99c31f185009ce229460fc338d4fcee2e23c87e72c8fde52b92406cee0105";
    /** Golden fee: 1000 × (2×948 + 1×384 + 100) — kit's fees::estimate_fee. */
    private static final long EXPECTED_FEE = 2_380_000;

    static boolean shieldAndParamsAvailable() {
        return ShieldKeys.isAvailable() && new SaplingParams(SaplingParams.defaultDir()).present();
    }

    /**
     * Shield state with one pinned note (the kit's offline golden note for
     * the test mnemonic, witnessed at position 0 on a fresh tree). The
     * nullifier is set the way a real sync would populate it.
     */
    private ShieldState stateWithNote(int birthdayHeight) throws Exception {
        SerializedNote note = new SerializedNote(
                JsonParser.object().from(NOTE_JSON), WITNESS_HEX, EXPECTED_NULLIFIER, null, birthdayHeight);
        return new ShieldState(birthdayHeight, "", List.of(note));
    }

    /** Wallet JSON with the pinned note, built through the production facade. */
    private String buildWalletJsonWithNote(String mnemonic, int birthdayHeight) throws Exception {
        return ShieldSendService.buildWalletJson(
                mnemonic, birthdayHeight, stateWithNote(birthdayHeight));
    }

    @Test
    @EnabledIf("shieldAndParamsAvailable")
    void buildsAndSignsRealShieldTransaction() throws Exception {
        SaplingParams params = new SaplingParams(SaplingParams.defaultDir());
        ShieldState state = stateWithNote(5_000_000);

        // One-call facade: state → walletJson → JNI → parsed result.
        ShieldTxResult result = ShieldSendService.createTransaction(
                TEST_MNEMONIC, 5_000_000, state,
                // Self-send to the wallet's own default shield address.
                "ps124f3dxhmtygh72cu8f05t94yey59at3armnk44uctjwdqf9uk2grnth3h5uszmqzzeev7kcr7rn",
                5_000_000L, "jpivx test", 5_000_001L, params);

        assertNotNull(result.txhex());
        assertTrue(result.txhex().startsWith("030000"), "v3 transaction: " +
                result.txhex().substring(0, 24));
        assertEquals(5_000_000L, result.amount());
        assertEquals(EXPECTED_FEE, result.fee());
        assertEquals(List.of(EXPECTED_NULLIFIER), result.nullifiers(),
                "nullifier must equal the kit's offline golden value");

        // Post-broadcast bookkeeping: the spent note leaves the state.
        assertEquals(1, state.removeSpentNotes(result.nullifiers()));
        assertEquals(0, state.getUnspentNotes().size());
    }

    /**
     * Shield → transparent ("deshield"): the kit adds ONE transparent output
     * to the {@code D...} recipient while the change stays shield. Fee shape
     * is (t_out=1, s_out=2) → shield fee + 34,000 sat.
     */
    @Test
    @EnabledIf("shieldAndParamsAvailable")
    void buildsDeshieldTransactionToTransparentAddress() throws Exception {
        String walletJson = buildWalletJsonWithNote(TEST_MNEMONIC, 5_000_000);
        SaplingParams params = new SaplingParams(SaplingParams.defaultDir());

        // Transparent address of the test mnemonic (verified cross-impl vector)
        String dest = "DPo9TNvPwy2ZfmVM3CRCxbBvh6NojguWXJ";
        String resultJson = ShieldKeys.createShieldTransaction(
                walletJson, dest, 5_000_000L, "", 5_000_001L,
                params.spendPath().toString(), params.outputPath().toString());
        ShieldTxResult result = ShieldTxResult.fromJson(JsonParser.object().from(resultJson));

        assertEquals(5_000_000L, result.amount());
        assertEquals(EXPECTED_FEE + 34_000L, result.fee(), "1 extra transparent output (34 bytes × 1000 sat)");
        assertEquals(List.of(EXPECTED_NULLIFIER), result.nullifiers());

        // The recipient's P2PKH scriptPubKey must literally appear in the tx.
        String recipientScript = HexFormat.of().formatHex(
                PivxAddress.addressToP2pkhScript(dest));
        assertTrue(result.txhex().contains(recipientScript),
                "tx must pay out to the transparent destination script");
    }

    /**
     * End-to-end {@code --subtract-fee}: with the pinned 10M note and a 5M
     * budget, the recipient lands at budget − fee and the builder charges
     * precisely the fixpoint fee — so recipient + fee == 5M exactly.
     */
    @Test
    @EnabledIf("shieldAndParamsAvailable")
    void subtractFeeChargesExactlyTheBudget() throws Exception {
        ShieldState state = stateWithNote(5_000_000);

        long budget = 5_000_000L;
        String dest = "ps124f3dxhmtygh72cu8f05t94yey59at3armnk44uctjwdqf9uk2grnth3h5uszmqzzeev7kcr7rn";
        // Typed overload: notes + destination, no manual JSON.
        long recipientSat = ShieldSendService.resolveSubtractFeeAmount(
                state.getUnspentNotes(), budget, dest);
        assertEquals(budget - EXPECTED_FEE, recipientSat);

        SaplingParams params = new SaplingParams(SaplingParams.defaultDir());
        ShieldTxResult result = ShieldSendService.createTransaction(
                TEST_MNEMONIC, 5_000_000, state, dest, recipientSat, "", 5_000_001L, params);

        assertEquals(budget - EXPECTED_FEE, result.amount(), "recipient gets budget − fee");
        assertEquals(EXPECTED_FEE, result.fee(), "builder's fee matches the fixpoint");
        assertEquals(budget, result.amount() + result.fee(), "total charged == budget");
    }
}
