package dev.jpivx.wallet.shield;

import java.io.IOException;

import dev.jpivx.wallet.core.PivAmount;

/**
 * Shared subtract-fee / send-max solver for the two shield-side builders
 * ({@link ShieldSendService} spends notes, {@link ShieldingService} spends
 * transparent UTXOs — only the fee quote differs).
 *
 * <p>Finds the <b>largest</b> recipient amount {@code a} such that the
 * builder can actually construct the transaction and
 * {@code a + fee(a) <= budgetSat}, where {@code fee(a)} is the exact fee the
 * builder's own selection charges for {@code a}. When the budget is fully
 * consumable this is exactly {@code budget - fee} ({@code a + fee == budget});
 * when it is not — e.g. a send-max whose smallest coin cannot pay for its own
 * inclusion — the result is the closest feasible amount below it, never an
 * error and never an unsendable number.
 *
 * <p>Solved by binary search rather than a fee-fixpoint iteration: the fee
 * is a step function of the amount (it jumps when the selection pulls in
 * another input), so a naive {@code fee -> budget - fee -> re-select} loop
 * can oscillate forever across a step boundary. Feasibility is monotone in
 * the amount (a smaller amount never needs more inputs), so binary search is
 * exact and always terminates in &le; 63 quotes.
 */
final class SubtractFee {

    private SubtractFee() {
        throw new AssertionError("no instances");
    }

    /** One selection round: the exact builder fee for {@code amountSat},
     *  throwing {@link IllegalArgumentException} when the wallet's coins
     *  cannot cover {@code amountSat} plus that fee. */
    @FunctionalInterface
    interface FeeQuote {
        long fee(long amountSat) throws IOException;
    }

    /**
     * Solve the send-max amount for {@code budgetSat}.
     *
     * @param budgetSat    total sats the wallet may lose (recipient + fee)
     * @param spendableSat the wallet's total spendable balance — budgets
     *                     beyond it are caller errors (stale balance), not
     *                     send-max requests
     * @param feeLabel     "shield" / "shielding", for error messages
     * @param quote        the builder's own selection (see {@link FeeQuote})
     * @return the largest feasible recipient amount (see class doc)
     * @throws IllegalArgumentException if {@code budgetSat} exceeds
     *         {@code spendableSat} or cannot cover the smallest possible fee
     */
    static long resolve(long budgetSat, long spendableSat, String feeLabel, FeeQuote quote)
            throws IOException {
        if (budgetSat > spendableSat) {
            throw new IllegalArgumentException(
                    "Insufficient balance: budget " + PivAmount.formatSatToPiv(budgetSat)
                            + " exceeds the spendable " + PivAmount.formatSatToPiv(spendableSat));
        }
        // Propagates real quote errors (malformed notes/UTXOs, balance below
        // the minimal one-input fee) instead of masking them as "infeasible".
        long minFee = quote.fee(0);
        // fee(a) >= minFee, so a + fee(a) <= budget bounds a here. When
        // hi <= 0 the loop never runs and the post-loop throw fires.
        long hi = budgetSat - minFee;

        long lo = 1;
        long best = -1;
        while (lo <= hi) {
            long mid = lo + (hi - lo) / 2;
            Long fee = tryQuote(quote, mid);
            if (fee != null && mid <= budgetSat - fee) {
                best = mid;
                lo = mid + 1;
            } else {
                hi = mid - 1;
            }
        }
        if (best < 0) {
            throw tooSmall(budgetSat, minFee, feeLabel);
        }
        return best;
    }

    /** A quote that cannot cover {@code amount + fee} reads as infeasible. */
    private static Long tryQuote(FeeQuote quote, long amountSat) throws IOException {
        try {
            return quote.fee(amountSat);
        } catch (IllegalArgumentException infeasible) {
            return null;
        }
    }

    private static IllegalArgumentException tooSmall(long budgetSat, long minFee, String feeLabel) {
        return new IllegalArgumentException("Amount " + PivAmount.formatSatToPiv(budgetSat)
                + " is too small to cover the " + feeLabel + " fee "
                + PivAmount.formatSatToPiv(minFee) + ".");
    }
}
