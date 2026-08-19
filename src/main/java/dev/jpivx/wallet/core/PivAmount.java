package dev.jpivx.wallet.core;

import java.math.BigInteger;

/**
 * PIV amount parsing and formatting.
 *
 * <p>All amounts are carried internally as {@code long} satoshis (1 PIV = 10^8 sat).
 * Uses exact integer arithmetic — no floating point conversion — so round-trip
 * parsing preserves every satoshi. Maximum 8 decimal places; more is rejected.
 *
 * <p>Mirrors {@code src/amount.rs} of the Rust {@code pivx-wallet-kit}. The Rust
 * code operates on {@code u64}; we use {@link BigInteger} for the multiply/add
 * path so the overflow semantics match exactly (a value that overflows
 * {@code u64} satoshis is rejected with an exception, never silently wrapped).
 */
public final class PivAmount {

    private static final BigInteger COIN_BI = BigInteger.valueOf(PivxParams.COIN);
    private static final BigInteger LONG_MAX = BigInteger.valueOf(Long.MAX_VALUE);
    private static final BigInteger[] POW10 = new BigInteger[9];
    static {
        for (int i = 0; i < POW10.length; i++) {
            POW10[i] = BigInteger.TEN.pow(i);
        }
    }

    private PivAmount() {
        throw new AssertionError("no instances");
    }

    /**
     * Parse a PIV amount string (e.g. {@code "1.23456789"}) into satoshis.
     *
     * @param s the amount string; leading/trailing whitespace is trimmed
     * @return satoshis as a non-negative {@code long}
     * @throws ArithmeticException if the amount overflows {@code u64} satoshis
     * @throws IllegalArgumentException if the string is empty or malformed
     */
    public static long parsePivToSat(String s) {
        String trimmed = s.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("Empty amount");
        }

        int dot = trimmed.indexOf('.');
        int lastDot = trimmed.lastIndexOf('.');
        if (dot != lastDot) {
            throw new IllegalArgumentException("Invalid amount format");
        }

        BigInteger integerPart;
        BigInteger fractionalSat;
        if (dot < 0) {
            integerPart = parseNonNegative(trimmed);
            fractionalSat = BigInteger.ZERO;
        } else {
            String intStr = trimmed.substring(0, dot);
            String fracStr = trimmed.substring(dot + 1);
            if (intStr.isEmpty() && fracStr.isEmpty()) {
                throw new IllegalArgumentException("Invalid amount format");
            }
            integerPart = intStr.isEmpty() ? BigInteger.ZERO : parseNonNegative(intStr);

            if (fracStr.length() > 8) {
                throw new IllegalArgumentException("Too many decimal places (max 8)");
            }
            if (fracStr.isEmpty()) {
                fractionalSat = BigInteger.ZERO;
            } else {
                BigInteger fracVal = parseNonNegative(fracStr);
                int shift = 8 - fracStr.length();
                fractionalSat = fracVal.multiply(POW10[shift]);
            }
        }

        BigInteger integerSat = integerPart.multiply(COIN_BI);
        BigInteger total = integerSat.add(fractionalSat);

        if (total.signum() < 0 || total.compareTo(LONG_MAX) > 0) {
            throw new ArithmeticException("Amount overflow");
        }
        return total.longValue();
    }

    /**
     * Format a satoshi amount as a PIV string, always with 8 decimal places.
     *
     * @param sat satoshis (non-negative)
     * @return formatted string, e.g. {@code "1.23456789"} for {@code 123_456_789}
     */
    public static String formatSatToPiv(long sat) {
        if (sat < 0) {
            throw new IllegalArgumentException("sat must be non-negative: " + sat);
        }
        long integer = sat / PivxParams.COIN;
        long fractional = sat % PivxParams.COIN;
        StringBuilder sb = new StringBuilder();
        sb.append(integer).append('.');
        String frac = Long.toString(fractional);
        for (int i = frac.length(); i < 8; i++) {
            sb.append('0');
        }
        sb.append(frac);
        return sb.toString();
    }

    private static BigInteger parseNonNegative(String s) {
        // Reject leading sign — matches Rust's u64 parser, which does not
        // accept "+5" or "-0". BigInteger would otherwise accept "-0" as 0
        // (signum 0), letting malformed inputs like "-0.5" slip through.
        if (!s.isEmpty() && (s.charAt(0) == '-' || s.charAt(0) == '+')) {
            throw new IllegalArgumentException("Invalid amount: " + s);
        }
        try {
            BigInteger v = new BigInteger(s);
            if (v.signum() < 0) {
                throw new IllegalArgumentException("Invalid amount: " + s);
            }
            return v;
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid amount: " + s, e);
        }
    }
}
