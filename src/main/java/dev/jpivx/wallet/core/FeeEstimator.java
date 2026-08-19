package dev.jpivx.wallet.core;

/**
 * Component-based fee estimation for PIVX transactions.
 *
 * <p>Mirrors {@code src/fees.rs} of the Rust {@code pivx-wallet-kit}. Two flat-rate
 * models:
 * <ul>
 *   <li>{@link #estimateFee} — 1000 sat/byte for v3/Sapling-shaped transactions.</li>
 *   <li>{@link #estimateRawTransparentFee} — 10 sat/byte for legacy v1 P2PKH.</li>
 * </ul>
 */
public final class FeeEstimator {

    private FeeEstimator() {
        throw new AssertionError("no instances");
    }

    /**
     * Estimate the fee (in satoshis) for a transaction by component count.
     *
     * <p>Flat rate of 1000 sat/byte applied to a conservative size model:
     * <ul>
     *   <li>948 bytes per Sapling output</li>
     *   <li>384 bytes per Sapling input</li>
     *   <li>180 bytes per transparent input (signed P2PKH)</li>
     *   <li>34 bytes per transparent output</li>
     *   <li>100 bytes of transaction overhead</li>
     * </ul>
     *
     * @param transparentInputCount  number of transparent inputs
     * @param transparentOutputCount number of transparent outputs
     * @param saplingInputCount      number of Sapling spends
     * @param saplingOutputCount     number of Sapling outputs
     * @return fee in satoshis
     */
    public static long estimateFee(long transparentInputCount,
                                   long transparentOutputCount,
                                   long saplingInputCount,
                                   long saplingOutputCount) {
        final long FEE_PER_BYTE = 1000L;
        return FEE_PER_BYTE * (saplingOutputCount * 948L
                + saplingInputCount * 384L
                + transparentInputCount * 180L
                + transparentOutputCount * 34L
                + 100L);
    }

    /**
     * Legacy v1 transparent-only fee estimator (10 sat/byte).
     *
     * <p>Used by the raw P2PKH builder that bypasses the librustpivx v3
     * transaction format. Matches the pre-kit agent-kit behaviour:
     * ~150 bytes/input, ~34 bytes/output, ~10 bytes overhead.
     *
     * @param inputCount  number of transparent inputs
     * @param outputCount number of transparent outputs
     * @return fee in satoshis
     */
    public static long estimateRawTransparentFee(int inputCount, int outputCount) {
        long estSize = (long) inputCount * 150L + (long) outputCount * 34L + 10L;
        return estSize * 10L;
    }
}
