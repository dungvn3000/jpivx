package dev.jpivx.wallet.shield;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;

import dev.jpivx.wallet.crypto.ShieldKeys;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Fixpoint tests for {@code --subtract-fee}. These use fabricated note JSON —
 * {@code selectShieldNotes} only reads {@code note.value} and {@code memo}, so
 * no valid crypto material is required and NO proving params are needed.
 * Enabled only when the native library is loaded.
 */
class ShieldSubtractFeeTest {

    static boolean shieldAvailable() {
        return ShieldKeys.isAvailable();
    }

    /** Kit's fees::estimate_fee for (t_out=0, s_in=N, s_out=2) = 1_996_000 + 384_000·N. */
    private static final long FEE_1_SPEND = 2_380_000;
    private static final long FEE_2_SPENDS = 2_764_000;

    private static String notesJson(long... values) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < values.length; i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append("{\"note\":{\"value\":").append(values[i])
                    .append("},\"witness\":\"\",\"nullifier\":\"\",\"memo\":null,\"height\":0}");
        }
        return sb.append(']').toString();
    }

    @Test
    @EnabledIf("shieldAvailable")
    void singleNoteRecipientGetsBudgetMinusFee() throws Exception {
        // Budget 5_000_000; one 10M note → 1 spend, fee 2_380_000 → recipient 2_620_000.
        long send = ShieldSendService.resolveSubtractFeeAmount(notesJson(10_000_000L), 5_000_000L, 0);
        assertEquals(5_000_000L - FEE_1_SPEND, send);
    }

    @Test
    @EnabledIf("shieldAvailable")
    void convergesAcrossTwoNotes() throws Exception {
        // Notes 4M + 2M, budget 5.5M:
        //   round 0: fee = 2.38M (1-spend guess) → send = 3.12M
        //     select(3.12M): 4M < 3.12M+2.764M → 2 notes → fee 2.764M
        //   round 1: send = 2_736_000 → select: still needs 2 notes, fee 2.764M == fee → done.
        long send = ShieldSendService.resolveSubtractFeeAmount(
                notesJson(4_000_000L, 2_000_000L), 5_500_000L, 0);
        assertEquals(5_500_000L - FEE_2_SPENDS, send);
    }

    @Test
    @EnabledIf("shieldAvailable")
    void deshieldShapeChargesOneExtraTransparentOutput() throws Exception {
        // Same as single-note but t_out=1: fee grows by exactly 34,000 sat.
        long send = ShieldSendService.resolveSubtractFeeAmount(notesJson(10_000_000L), 5_000_000L, 1);
        assertEquals(5_000_000L - (FEE_1_SPEND + 34_000L), send);
    }

    @Test
    @EnabledIf("shieldAvailable")
    void budgetBelowFeeErrors() {
        // 1M budget is smaller than the 2.38M one-spend shield fee.
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
                ShieldSendService.resolveSubtractFeeAmount(notesJson(10_000_000L), 1_000_000L, 0));
        assertTrue(ex.getMessage().contains("too small"), ex.getMessage());
    }

    @Test
    @EnabledIf("shieldAvailable")
    void budgetBeyondNoteTotalErrors() {
        // Budget bigger than all notes combined → caller error (stale balance),
        // rejected before any selection round.
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
                ShieldSendService.resolveSubtractFeeAmount(notesJson(1_000L), 1_000_000_000L, 0));
        assertTrue(ex.getMessage().contains("exceeds the spendable"), ex.getMessage());
    }

    /**
     * The step-boundary window that broke the old fee-fixpoint: a full-balance
     * budget where the 1-spend guess overshoots what one note can cover. The
     * solver must land on the 2-spend amount (recipient + fee == budget)
     * instead of erroring out of the kit's selection.
     */
    @Test
    @EnabledIf("shieldAvailable")
    void sendMaxAcrossFeeStepFindsFeasibleAmount() throws Exception {
        // Notes 400M + 500M, budget = whole balance 900M.
        //   1-spend guess: send 900M − 2.38M = 897.62M → needs both notes,
        //   but 900M < 897.62M + 2.764M → the old loop died here.
        long send = ShieldSendService.resolveSubtractFeeAmount(
                notesJson(400_000_000L, 500_000_000L), 900_000_000L, 0);
        assertEquals(900_000_000L - FEE_2_SPENDS, send);
    }
}
