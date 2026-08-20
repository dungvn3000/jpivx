package dev.jpivx.wallet.tx;

import dev.jpivx.wallet.core.FeeEstimator;
import dev.jpivx.wallet.core.Utxo;

import java.util.*;

/**
 * UTXO coin selection algorithms for PIVX P2PKH transparent transactions.
 *
 * <p>Provides two strategies (Apache 2.0, adapted from
 * <a href="https://github.com/sparrowwallet/drongo">sparrowwallet/drongo</a>):
 * <ul>
 *   <li>{@link #selectBnB} — Branch-and-Bound: finds an exact-match input set that
 *       avoids a change output, minimising fees and improving privacy.</li>
 *   <li>{@link #selectKnapsack} — Knapsack: randomised fallback that reliably finds a
 *       sufficient input set when BnB cannot find an exact match.</li>
 *   <li>{@link #select} — convenience method that tries BnB first, falls back to
 *       Knapsack automatically.</li>
 * </ul>
 *
 * <p>All methods operate on PIVX v1 P2PKH transaction cost model:
 * <ul>
 *   <li>Overhead: 10 bytes</li>
 *   <li>Per transparent input (signed P2PKH): 150 bytes</li>
 *   <li>Per transparent output: 34 bytes</li>
 *   <li>Fee rate: 10 sat/byte</li>
 * </ul>
 */
public final class CoinSelector {

    // -------------------------------------------------------------------------
    // PIVX v1 P2PKH cost model (matches FeeEstimator.estimateRawTransparentFee)
    // -------------------------------------------------------------------------

    /** Fee rate for legacy v1 P2PKH transactions (sat/byte). */
    public static final long FEE_RATE = 10L;

    /** Virtual size of a signed P2PKH input (bytes). */
    public static final long INPUT_VBYTES = 150L;

    /** Virtual size of a P2PKH output (bytes). */
    public static final long OUTPUT_VBYTES = 34L;

    /** Transaction overhead (version + locktime + varint headers, bytes). */
    public static final long OVERHEAD_VBYTES = 10L;

    /**
     * Minimum change output value to bother creating one (in satoshis).
     * Below this threshold it is cheaper to donate to miners.
     */
    public static final long MIN_CHANGE = 546L; // dust threshold

    /** Maximum BnB iterations before giving up. */
    private static final int BNB_TOTAL_TRIES = 100_000;

    private CoinSelector() {
        throw new AssertionError("no instances");
    }

    // =========================================================================
    // Public API
    // =========================================================================

    /**
     * Select UTXOs using BnB first; fall back to Knapsack if BnB cannot find
     * an exact match.
     *
     * @param candidates available UTXOs (not modified)
     * @param amount     the payment amount in satoshis
     * @param nOutputs   number of outputs (1 = payment only, 2 = payment + change)
     * @return selected UTXOs; never empty
     * @throws IllegalArgumentException if balance is insufficient
     */
    public static List<Utxo> select(List<Utxo> candidates, long amount, int nOutputs) {
        // Try BnB for a changeless solution (nOutputs = 1)
        Optional<List<Utxo>> bnbResult = selectBnB(candidates, amount, 1);
        // Fall back to Knapsack which may produce change
        return bnbResult.orElseGet(() -> selectKnapsack(candidates, amount, nOutputs));
    }

    /**
     * Branch-and-Bound coin selection (adapted from Drongo / Bitcoin Core).
     *
     * <p>Finds a subset of {@code candidates} whose effective value (amount minus
     * input fee) falls within [{@code target}, {@code target + MIN_CHANGE}],
     * thereby avoiding a change output entirely.
     *
     * @param candidates available UTXOs
     * @param amount     payment amount in satoshis
     * @param nOutputs   intended output count (use 1 for changeless attempt)
     * @return the selected set, or {@link Optional#empty()} if no exact match found
     */
    public static Optional<List<Utxo>> selectBnB(List<Utxo> candidates, long amount, int nOutputs) {
        // Base fee excluding input costs (outputs + overhead)
        long baseFee = (nOutputs * OUTPUT_VBYTES + OVERHEAD_VBYTES) * FEE_RATE;
        long inputFeeEach = INPUT_VBYTES * FEE_RATE;

        // effectiveValue = utxo.amount() - cost_of_spending_it
        // Index explicitly (never indexOf: equal-valued UTXOs are distinct outpoints).
        List<long[]> pool = new ArrayList<>(candidates.size());
        for (int i = 0; i < candidates.size(); i++) {
            long eff = candidates.get(i).amount() - inputFeeEach;
            if (eff > 0) { // skip dust UTXOs whose fee exceeds value
                pool.add(new long[]{ eff, i });
            }
        }
        pool.sort((a, b) -> Long.compare(b[0], a[0])); // descending

        long currentAvailable = pool.stream().mapToLong(e -> e[0]).sum();
        if (currentAvailable < amount) {
            return Optional.empty(); // can't even cover payment
        }

        // actualTarget: effective sum must be in [amount + baseFee, amount + baseFee + MIN_CHANGE]
        long actualTarget = amount + baseFee;
        long upperBound   = actualTarget + MIN_CHANGE;

        ArrayDeque<Boolean> currentSelection = new ArrayDeque<>(pool.size());
        long currentValue = 0;
        long currentAvailableValue = currentAvailable;

        ArrayDeque<Boolean> bestSelection = null;
        long bestWaste = Long.MAX_VALUE;

        for (int i = 0; i < BNB_TOTAL_TRIES; i++) {
            boolean backtrack = false;

            if (currentValue + currentAvailableValue < actualTarget
                    || currentValue > upperBound) {
                backtrack = true;
            } else if (currentValue >= actualTarget) {
                // Candidate solution: compute waste
                long waste = currentValue - actualTarget;
                if (waste < bestWaste) {
                    bestWaste = waste;
                    bestSelection = new ArrayDeque<>(currentSelection);
                }
                backtrack = true;
            }

            if (backtrack) {
                // Pop until we find a true branch, then flip it to false
                while (!currentSelection.isEmpty() && !currentSelection.peekLast()) {
                    currentSelection.pollLast();
                    int idx = currentSelection.size();
                    if (idx < pool.size()) {
                        currentAvailableValue += pool.get(idx)[0];
                    }
                }
                if (currentSelection.isEmpty()) break; // exhausted
                // Flip the last "true" to "false"
                currentSelection.pollLast();
                int idx = currentSelection.size();
                if (idx < pool.size()) {
                    currentValue -= pool.get(idx)[0];
                    currentSelection.addLast(false);
                }
            } else {
                // Explore: include or exclude next element
                int idx = currentSelection.size();
                if (idx >= pool.size()) break;
                currentAvailableValue -= pool.get(idx)[0];
                // Try including first
                currentValue += pool.get(idx)[0];
                currentSelection.addLast(true);
            }
        }

        if (bestSelection == null) {
            return Optional.empty();
        }

        // Reconstruct selected UTXOs
        List<Boolean> selList = new ArrayList<>(bestSelection);
        List<Utxo> selected = new ArrayList<>();
        for (int i = 0; i < selList.size() && i < pool.size(); i++) {
            if (selList.get(i)) {
                selected.add(candidates.get((int) pool.get(i)[1]));
            }
        }
        return selected.isEmpty() ? Optional.empty() : Optional.of(selected);
    }

    /**
     * Knapsack coin selection (adapted from Drongo / Bitcoin Core).
     *
     * <p>Shuffles candidates randomly, then tries to find a subset summing to the
     * target. Falls back to the smallest single UTXO that covers the target.
     *
     * @param candidates available UTXOs
     * @param amount     payment amount in satoshis
     * @param nOutputs   intended output count
     * @return the selected set
     * @throws IllegalArgumentException if the balance is insufficient
     */
    public static List<Utxo> selectKnapsack(List<Utxo> candidates, long amount, int nOutputs) {
        if (candidates.isEmpty()) {
            throw new IllegalArgumentException("No UTXOs available");
        }

        long inputFeeEach = INPUT_VBYTES * FEE_RATE;
        long baseFee      = (nOutputs * OUTPUT_VBYTES + OVERHEAD_VBYTES) * FEE_RATE;

        List<Utxo> shuffled = new ArrayList<>(candidates);
        Collections.shuffle(shuffled);

        // Target effective amount
        long actualTarget = amount + baseFee;

        // 1. Look for a single UTXO that exactly matches
        long singleInputFee = baseFee + inputFeeEach; // fee with exactly 1 input
        for (Utxo u : shuffled) {
            if (u.amount() - singleInputFee == amount) {
                return List.of(u);
            }
        }

        // 2. Collect UTXOs smaller than target, keep track of smallest above target
        Utxo lowestLarger = null;
        List<Utxo> applicableGroups = new ArrayList<>();
        long totalLower = 0;

        for (Utxo u : shuffled) {
            long eff = u.amount() - inputFeeEach;
            if (eff <= 0) continue; // skip dust

            if (eff < actualTarget + MIN_CHANGE) {
                applicableGroups.add(u);
                totalLower += eff;
            } else {
                if (lowestLarger == null
                        || (u.amount() - inputFeeEach) < (lowestLarger.amount() - inputFeeEach)) {
                    lowestLarger = u;
                }
            }
        }

        if (totalLower == actualTarget) {
            return applicableGroups;
        }

        if (totalLower < actualTarget) {
            // Can only reach target if we include lowestLarger
            if (lowestLarger == null) {
                throw new IllegalArgumentException(
                        "Insufficient balance: available " + totalEffective(candidates, inputFeeEach)
                        + " sat, need " + actualTarget + " sat");
            }
            return List.of(lowestLarger);
        }

        // 3. Subset sum: try random subsets of applicableGroups
        List<Utxo> bestResult = null;
        long bestTotal = Long.MAX_VALUE;

        for (int attempt = 0; attempt < 1000; attempt++) {
            Collections.shuffle(applicableGroups);
            List<Utxo> current = new ArrayList<>();
            long runningTotal = 0;

            for (Utxo u : applicableGroups) {
                long eff = u.amount() - inputFeeEach;
                current.add(u);
                runningTotal += eff;
                if (runningTotal >= actualTarget) {
                    if (runningTotal < bestTotal) {
                        bestTotal = runningTotal;
                        bestResult = new ArrayList<>(current);
                    }
                    break;
                }
            }
        }

        if (bestResult != null) {
            return bestResult;
        }

        // 4. Last resort: use lowestLarger if available
        if (lowestLarger != null) {
            return List.of(lowestLarger);
        }

        throw new IllegalArgumentException(
                "Insufficient balance: available " + totalEffective(candidates, inputFeeEach)
                + " sat effective, need " + actualTarget + " sat");
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /** Compute total effective value of a UTXO list (amount minus input fee each). */
    public static long totalEffective(List<Utxo> utxos, long inputFeeEach) {
        return utxos.stream().mapToLong(u -> Math.max(0, u.amount() - inputFeeEach)).sum();
    }

    /**
     * Calculate the fee for a transaction with the given input/output counts
     * using the PIVX P2PKH cost model.
     *
     * @param nInputs  number of inputs
     * @param nOutputs number of outputs
     * @return fee in satoshis
     */
    public static long estimateFee(int nInputs, int nOutputs) {
        return FeeEstimator.estimateRawTransparentFee(nInputs, nOutputs);
    }

}
