package dev.jpivx.wallet.core;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Port of {@code parse_piv_*} and {@code format_sat_*} tests from
 * {@code tests/integration.rs}.
 */
class PivAmountTest {

    @Test
    void parsePivBasicCases() {
        assertEquals(100_000_000L, PivAmount.parsePivToSat("1"));
        assertEquals(1L, PivAmount.parsePivToSat("0.00000001"));
        assertEquals(123_456_789L, PivAmount.parsePivToSat("1.23456789"));
        assertEquals(1_000_000_000L, PivAmount.parsePivToSat("  10  "));
        assertEquals(100_000_000L, PivAmount.parsePivToSat("1."));
        assertEquals(150_000_000L, PivAmount.parsePivToSat("1.5"));
    }

    @Test
    void parsePivRejectsMalformed() {
        assertThrows(IllegalArgumentException.class, () -> PivAmount.parsePivToSat(""));
        assertThrows(IllegalArgumentException.class, () -> PivAmount.parsePivToSat("abc"));
        assertThrows(IllegalArgumentException.class, () -> PivAmount.parsePivToSat("1.2.3"));
        assertThrows(IllegalArgumentException.class, () -> PivAmount.parsePivToSat("1.123456789")); // 9 decimals
        assertThrows(IllegalArgumentException.class, () -> PivAmount.parsePivToSat("1e10"));
    }

    @Test
    void parsePivRejectsNegative() {
        assertThrows(IllegalArgumentException.class, () -> PivAmount.parsePivToSat("-1"));
        assertThrows(IllegalArgumentException.class, () -> PivAmount.parsePivToSat("-0.5"));
    }

    @Test
    void parsePivOverflow() {
        // u64::MAX — must be rejected as overflow (mirrors the Rust test).
        assertThrows(ArithmeticException.class,
                () -> PivAmount.parsePivToSat(Long.toUnsignedString(-1L)));
        // A satoshi value just over Long.MAX_VALUE — also overflow.
        assertThrows(ArithmeticException.class,
                () -> PivAmount.parsePivToSat("9223372036854775808"));
    }

    @Test
    void formatSatRoundTripsThroughParse() {
        long[] samples = {0L, 1L, 100L, 100_000_000L, 123_456_789L, 1_000_000_000_000L};
        for (long sat : samples) {
            String formatted = PivAmount.formatSatToPiv(sat);
            long round = PivAmount.parsePivToSat(formatted);
            assertEquals(sat, round, "round-trip failed for " + sat);
        }
    }

    @Test
    void formatSatAlwaysHasEightDecimals() {
        assertEquals("0.00000000", PivAmount.formatSatToPiv(0));
        assertEquals("0.00000001", PivAmount.formatSatToPiv(1));
        assertEquals("1.00000000", PivAmount.formatSatToPiv(100_000_000));
        assertEquals("1.23456789", PivAmount.formatSatToPiv(123_456_789));
    }

    @Test
    void formatSatRejectsNegative() {
        assertThrows(IllegalArgumentException.class, () -> PivAmount.formatSatToPiv(-1));
    }
}
