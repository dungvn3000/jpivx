package dev.jpivx.wallet.shield;

import com.grack.nanojson.JsonParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;

import java.util.List;

import dev.jpivx.wallet.core.FeeEstimator;
import dev.jpivx.wallet.core.Utxo;
import dev.jpivx.wallet.crypto.ShieldKeys;
import dev.jpivx.wallet.tx.TransparentTransactionResult;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Shielding (transparent → shield) path. Argument checks run everywhere;
 * selection/fee tests need the native library (the kit's
 * {@code select_shielding_utxos} over JNI, no proving params); the full
 * Groth16 build is additionally gated on cached Sapling params (mirrors
 * {@link ShieldSendFullJniTest}).
 *
 * <p>The Groth16 test spends a synthetic UTXO — validly signed but not
 * broadcastable, since the outpoint does not exist on chain. Cross-checked
 * against the Rust-side {@code build_real_shielding_tx_offline}.
 */
class ShieldingJniTest {

    private static final String TEST_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /** Wallet's own default shield address for {@link #TEST_MNEMONIC}. */
    private static final String SHIELD_DEST =
            "ps124f3dxhmtygh72cu8f05t94yey59at3armnk44uctjwdqf9uk2grnth3h5uszmqzzeev7kcr7rn";

    /** Golden fees: 1000 × (n×180 + 2×948 + 100) — kit's fees::estimate_fee. */
    private static final long FEE_ONE_INPUT = 2_176_000;
    private static final long FEE_TWO_INPUTS = 2_356_000;

    private static Utxo utxo(String txidChar, long amountSat) {
        return new Utxo(txidChar.repeat(64), 0, amountSat, "", 5_000_000);
    }

    static boolean shieldAvailable() {
        return ShieldKeys.isAvailable();
    }

    static boolean shieldAndParamsAvailable() {
        return ShieldKeys.isAvailable() && new SaplingParams(SaplingParams.defaultDir()).present();
    }

    // ---- argument checks (no native library needed) ----

    @Test
    void rejectsTransparentDestination() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () ->
                ShieldingService.createTransaction(TEST_MNEMONIC, List.of(utxo("a", 500_000_000L)),
                        "DPo9TNvPwy2ZfmVM3CRCxbBvh6NojguWXJ", 100_000_000L, 5_000_001L,
                        new SaplingParams(SaplingParams.defaultDir())));
        assertTrue(e.getMessage().contains("ps1"), e.getMessage());
    }

    @Test
    void rejectsUtxoFromAnotherHdIndex() {
        Utxo foreign = new Utxo("b".repeat(64), 0, 500_000_000L, "", 5_000_000, 7);
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () ->
                ShieldingService.createTransaction(TEST_MNEMONIC, List.of(foreign),
                        SHIELD_DEST, 100_000_000L, 5_000_001L,
                        new SaplingParams(SaplingParams.defaultDir())));
        assertTrue(e.getMessage().contains("hd_index=7"), e.getMessage());
    }

    @Test
    void rejectsEmptyUtxoSet() {
        assertThrows(IllegalArgumentException.class, () ->
                ShieldingService.createTransaction(TEST_MNEMONIC, List.of(),
                        SHIELD_DEST, 100_000_000L, 5_000_001L,
                        new SaplingParams(SaplingParams.defaultDir())));
    }

    @Test
    void rejectsNegativeUtxoAmount() {
        Utxo bogus = new Utxo("c".repeat(64), 0, -5L, "", 5_000_000);
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () ->
                ShieldingService.createTransaction(TEST_MNEMONIC, List.of(bogus),
                        SHIELD_DEST, 100_000_000L, 5_000_001L,
                        new SaplingParams(SaplingParams.defaultDir())));
        assertTrue(e.getMessage().contains("non-positive"), e.getMessage());
    }

    @Test
    void selectionFeeRejectsEmptyUtxoSet() {
        // A fee of 0 for an empty wallet would be a lie — must throw instead.
        assertThrows(IllegalArgumentException.class, () ->
                ShieldingService.selectionFee(List.of(), 100_000_000L));
    }

    // ---- selection / fee quote (kit's select_shielding_utxos over JNI) ----

    @Test
    @EnabledIf("shieldAvailable")
    void rejectsInsufficientBalance() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () ->
                ShieldingService.createTransaction(TEST_MNEMONIC, List.of(utxo("a", 1_000_000L)),
                        SHIELD_DEST, 100_000_000L, 5_000_001L,
                        new SaplingParams(SaplingParams.defaultDir())));
        assertTrue(e.getMessage().startsWith("Insufficient public balance"), e.getMessage());
    }

    @Test
    @EnabledIf("shieldAvailable")
    void selectionFeeMatchesTheKitsShape() throws Exception {
        List<Utxo> one = List.of(utxo("a", 500_000_000L));
        assertEquals(FEE_ONE_INPUT, ShieldingService.selectionFee(one, 100_000_000L));
        // Fee shape: (n transparent inputs, 0 transparent outs, 0 spends, 2 sapling outs).
        assertEquals(FeeEstimator.estimateFee(1, 0, 0, 2),
                ShieldingService.selectionFee(one, 100_000_000L));
    }

    @Test
    @EnabledIf("shieldAvailable")
    void selectionPullsInASecondUtxoAndChargesForIt() throws Exception {
        List<Utxo> two = List.of(utxo("a", 300_000_000L), utxo("b", 300_000_000L));
        // 3 PIV cannot cover 3 PIV + fee, so both inputs get selected.
        assertEquals(FEE_TWO_INPUTS, ShieldingService.selectionFee(two, 300_000_000L));
    }

    @Test
    @EnabledIf("shieldAvailable")
    void selectionFeeThrowsWhenAmountNotCoverable() {
        // The quote must agree with the build: no fee for an unbuildable send.
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () ->
                ShieldingService.selectionFee(List.of(utxo("a", 1_000_000L)), 100_000_000L));
        assertTrue(e.getMessage().startsWith("Insufficient public balance"), e.getMessage());
    }

    // ---- subtract-fee / send-max ----

    @Test
    @EnabledIf("shieldAvailable")
    void subtractFeeAmountLeavesExactlyTheFee() throws Exception {
        List<Utxo> utxos = List.of(utxo("a", 300_000_000L), utxo("b", 200_000_000L));
        long budget = 500_000_000L; // whole balance
        long amount = ShieldingService.resolveSubtractFeeAmount(utxos, budget);
        assertEquals(budget - FEE_TWO_INPUTS, amount);
        assertEquals(budget, amount + ShieldingService.selectionFee(utxos, amount));
    }

    /**
     * The oscillation window that broke the old fee-fixpoint: a dust UTXO
     * that cannot pay for its own inclusion. The solver must settle on the
     * best 1-input amount instead of bouncing between the 1- and 2-input
     * fee forever.
     */
    @Test
    @EnabledIf("shieldAvailable")
    void sendMaxWithUneconomicDustSettlesOnFeasibleAmount() throws Exception {
        List<Utxo> utxos = List.of(utxo("a", 500_000_000L), utxo("b", 100_000L));
        long budget = 500_100_000L; // whole balance; the 100k UTXO < 180k input cost
        long amount = ShieldingService.resolveSubtractFeeAmount(utxos, budget);
        // Best feasible: spend only the big coin — amount + 1-input fee = 5 PIV.
        assertEquals(500_000_000L - FEE_ONE_INPUT, amount);
        assertTrue(amount + ShieldingService.selectionFee(utxos, amount) <= budget);
    }

    @Test
    @EnabledIf("shieldAvailable")
    void subtractFeeRejectsBudgetBeyondSpendableBalance() {
        // A stale/bogus balance must error, not "converge" to an unsendable amount.
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () ->
                ShieldingService.resolveSubtractFeeAmount(
                        List.of(utxo("a", 500_000_000L)), 600_000_000L));
        assertTrue(e.getMessage().contains("exceeds the spendable"), e.getMessage());
    }

    @Test
    @EnabledIf("shieldAvailable")
    void subtractFeeRejectsABudgetBelowTheFee() {
        List<Utxo> utxos = List.of(utxo("a", 1_000_000L));
        assertThrows(IllegalArgumentException.class, () ->
                ShieldingService.resolveSubtractFeeAmount(utxos, 1_000_000L));
    }

    // ---- wallet JSON wiring + native hd_index guard ----

    @Test
    @EnabledIf("shieldAvailable")
    void walletJsonCarriesTheTransparentUtxos() throws Exception {
        String json = ShieldSendService.buildWalletJson(
                TEST_MNEMONIC, 5_000_000, new ShieldState(5_000_000, "", List.of()),
                List.of(utxo("a", 500_000_000L)));
        var utxos = JsonParser.object().from(json).getArray("unspent_utxos");
        assertEquals(1, utxos.size());
        assertEquals("a".repeat(64), utxos.getObject(0).getString("txid"));
        assertEquals(500_000_000L, utxos.getObject(0).getLong("amount"));
    }

    /**
     * The low-level path (buildWalletJson + ShieldKeys.createShieldingTransaction)
     * bypasses the facade's checks — the NATIVE layer must reject foreign-slot
     * UTXOs before signing them with the wrong key. Fires before the param
     * load, so no Sapling params are needed.
     */
    @Test
    @EnabledIf("shieldAvailable")
    void lowLevelPathRejectsForeignHdIndexNatively() throws Exception {
        Utxo foreign = new Utxo("b".repeat(64), 1, 500_000_000L, "", 5_000_000, 2);
        String walletJson = ShieldSendService.buildWalletJson(
                TEST_MNEMONIC, 5_000_000, new ShieldState(5_000_000, "", List.of()),
                List.of(foreign));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () ->
                ShieldKeys.createShieldingTransaction(walletJson, SHIELD_DEST,
                        100_000_000L, 5_000_001L, "/nonexistent", "/nonexistent"));
        assertTrue(e.getMessage().contains("hd_index=2"), e.getMessage());
    }

    // ---- full Groth16 path ----

    @Test
    @EnabledIf("shieldAndParamsAvailable")
    void buildsAndSignsRealShieldingTransaction() throws Exception {
        SaplingParams params = new SaplingParams(SaplingParams.defaultDir());

        TransparentTransactionResult result = ShieldingService.createTransaction(
                TEST_MNEMONIC, List.of(utxo("a", 500_000_000L)),
                SHIELD_DEST, 100_000_000L, 5_000_001L, params);

        assertTrue(result.txhex().startsWith("030000"),
                "v3 sapling transaction: " + result.txhex().substring(0, 24));
        assertEquals(100_000_000L, result.amount());
        assertEquals(FEE_ONE_INPUT, result.fee());
        assertEquals(1, result.spent().size());
        assertEquals("a".repeat(64), result.spent().get(0).txid());
        assertEquals(0, result.spent().get(0).vout());

        // Second build exercises the native prover cache (no ~50 MB re-read).
        TransparentTransactionResult again = ShieldingService.createTransaction(
                TEST_MNEMONIC, List.of(utxo("d", 400_000_000L)),
                SHIELD_DEST, 50_000_000L, 5_000_001L, params);
        assertEquals(50_000_000L, again.amount());
        assertEquals(FEE_ONE_INPUT, again.fee());
    }
}
