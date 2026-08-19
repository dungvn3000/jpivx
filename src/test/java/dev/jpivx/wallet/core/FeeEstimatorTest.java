package dev.jpivx.wallet.core;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Port of {@code fee_estimation_scales_with_sapling_io} and
 * {@code raw_transparent_fee_is_sane} from {@code tests/integration.rs}.
 */
class FeeEstimatorTest {

    @Test
    void feeEstimationScalesWithSaplingIo() {
        long base = FeeEstimator.estimateFee(0, 0, 0, 0);
        long oneSapling = FeeEstimator.estimateFee(0, 0, 0, 1);
        assertTrue(oneSapling > base);

        long twoSapling = FeeEstimator.estimateFee(0, 0, 0, 2);
        assertTrue(twoSapling > oneSapling);
        // Linear in outputs.
        assertEquals(twoSapling - oneSapling, oneSapling - base);
    }

    @Test
    void feeEstimationScalesWithTransparentIo() {
        long base = FeeEstimator.estimateFee(0, 0, 0, 0);
        long oneTIn = FeeEstimator.estimateFee(1, 0, 0, 0);
        long oneTOut = FeeEstimator.estimateFee(0, 1, 0, 0);
        assertTrue(oneTIn > base);
        assertTrue(oneTOut > base);
        // Transparent input is heavier than output.
        assertTrue(oneTIn > oneTOut);
    }

    @Test
    void feeEstimationScalesWithSaplingInputs() {
        long base = FeeEstimator.estimateFee(0, 0, 0, 0);
        long oneSIn = FeeEstimator.estimateFee(0, 0, 1, 0);
        long twoSIn = FeeEstimator.estimateFee(0, 0, 2, 0);
        // Linear in inputs: the +100 overhead is constant, so the marginal
        // cost of one input is oneSIn - base, and twoSIn - oneSIn equals it.
        assertEquals(oneSIn - base, twoSIn - oneSIn);
        assertEquals(1000L * 384, twoSIn - oneSIn);
    }

    @Test
    void rawTransparentFeeIsSane() {
        long oneIn = FeeEstimator.estimateRawTransparentFee(1, 2);
        long twoIn = FeeEstimator.estimateRawTransparentFee(2, 2);
        assertTrue(twoIn > oneIn);
        // Should be in a reasonable sat range (well under 1 PIV).
        assertTrue(oneIn < 100_000_000L);
    }

    @Test
    void rawTransparentFeeMatchesFixedSizeModel() {
        // input_count * 150 + output_count * 34 + 10, then *10 sat/byte.
        assertEquals(10L * (150 + 2 * 34 + 10), FeeEstimator.estimateRawTransparentFee(1, 2));
        assertEquals(10L * (2 * 150 + 2 * 34 + 10), FeeEstimator.estimateRawTransparentFee(2, 2));
        assertEquals(10L * 10, FeeEstimator.estimateRawTransparentFee(0, 0));
    }

    @Test
    void estimateFeeBaseIs100BytesOfOverhead() {
        assertEquals(1000L * 100, FeeEstimator.estimateFee(0, 0, 0, 0));
    }
}
