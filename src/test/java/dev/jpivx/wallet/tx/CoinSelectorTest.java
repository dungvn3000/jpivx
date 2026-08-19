package dev.jpivx.wallet.tx;

import org.junit.jupiter.api.Test;
import dev.jpivx.wallet.core.Utxo;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class CoinSelectorTest {

    // --- helpers ---

    private static Utxo utxo(long amount) {
        return new Utxo("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 0, amount, "", 0);
    }

    // -------------------------------------------------------------------------
    // estimateFee
    // -------------------------------------------------------------------------

    @Test
    void feeMatchesFeeEstimator() {
        // CoinSelector.estimateFee must agree with FeeEstimator.estimateRawTransparentFee
        for (int i = 1; i <= 5; i++) {
            for (int o = 1; o <= 3; o++) {
                long via_cs = CoinSelector.estimateFee(i, o);
                long via_fe = dev.jpivx.wallet.core.FeeEstimator.estimateRawTransparentFee(i, o);
                assertEquals(via_fe, via_cs,
                        "Fee mismatch for " + i + " inputs / " + o + " outputs");
            }
        }
    }

    // -------------------------------------------------------------------------
    // selectBnB
    // -------------------------------------------------------------------------

    @Test
    void bnbFindsExactMatchAvoidingChange() {
        // Fee for 1 input, 1 output: (150 + 34 + 10) * 10 = 1940
        long fee1in1out = CoinSelector.estimateFee(1, 1);
        long amount = 10_000L;
        // UTXO with amount == payment + fee → exact changeless match
        Utxo exact = utxo(amount + fee1in1out);
        Utxo extra  = utxo(100_000L);

        Optional<List<Utxo>> result = CoinSelector.selectBnB(List.of(exact, extra), amount, 1);
        assertTrue(result.isPresent(), "BnB should find exact match");
        assertEquals(1, result.get().size());
        assertEquals(exact.amount(), result.get().get(0).amount());
    }

    @Test
    void bnbReturnsEmptyWhenNoExactMatch() {
        // Two UTXOs that cannot sum to an exact target
        List<Utxo> candidates = List.of(utxo(5_000L), utxo(7_000L));
        // target = 20_000 — insufficient total anyway
        Optional<List<Utxo>> result = CoinSelector.selectBnB(candidates, 20_000L, 1);
        assertTrue(result.isEmpty(), "BnB should return empty when balance insufficient");
    }

    // -------------------------------------------------------------------------
    // selectKnapsack
    // -------------------------------------------------------------------------

    @Test
    void knapsackSelectsSingleSufficientUtxo() {
        Utxo big  = utxo(500_000L);
        Utxo small = utxo(1_000L);
        List<Utxo> result = CoinSelector.selectKnapsack(List.of(big, small), 10_000L, 2);
        assertFalse(result.isEmpty());
        assertTrue(result.stream().mapToLong(Utxo::amount).sum() > 10_000L);
    }

    @Test
    void knapsackThrowsWhenBalanceInsufficient() {
        List<Utxo> candidates = List.of(utxo(1_000L), utxo(2_000L));
        assertThrows(IllegalArgumentException.class,
                () -> CoinSelector.selectKnapsack(candidates, 1_000_000L, 2));
    }

    @Test
    void knapsackCombinesMultipleUtxos() {
        // 5 × 10_000 sat, target = 25_000 → must pick at least 3
        List<Utxo> candidates = List.of(
                utxo(10_000L), utxo(10_000L), utxo(10_000L), utxo(10_000L), utxo(10_000L));
        List<Utxo> result = CoinSelector.selectKnapsack(candidates, 25_000L, 2);
        assertFalse(result.isEmpty());
        long fee = CoinSelector.estimateFee(result.size(), 2);
        assertTrue(result.stream().mapToLong(Utxo::amount).sum() >= 25_000L + fee,
                "Selected amount must cover payment + fee");
    }

    // -------------------------------------------------------------------------
    // select (BnB → Knapsack composite)
    // -------------------------------------------------------------------------

    @Test
    void selectPrefersChangelessBnBSolution() {
        long fee1in1out = CoinSelector.estimateFee(1, 1);
        long amount = 50_000L;
        Utxo exact  = utxo(amount + fee1in1out);
        Utxo bigger = utxo(200_000L);

        List<Utxo> result = CoinSelector.select(List.of(exact, bigger), amount, 1);
        assertEquals(1, result.size(), "BnB exact match should be preferred");
    }

    @Test
    void selectFallsBackToKnapsackWhenBnBFails() {
        // No exact match possible, should still return a valid selection
        List<Utxo> candidates = List.of(utxo(20_000L), utxo(30_000L), utxo(15_000L));
        List<Utxo> result = CoinSelector.select(candidates, 10_000L, 2);
        assertFalse(result.isEmpty());
        long fee = CoinSelector.estimateFee(result.size(), 2);
        assertTrue(result.stream().mapToLong(Utxo::amount).sum() >= 10_000L + fee);
    }
}
