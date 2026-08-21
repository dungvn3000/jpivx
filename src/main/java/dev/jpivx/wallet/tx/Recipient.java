package dev.jpivx.wallet.tx;

/**
 * One output of a transparent transaction: who gets paid, and how much.
 *
 * <p>Used by the multi-output entry points of {@link RawTransparentBuilder} —
 * paying several destinations, or splitting one UTXO into several spendable
 * pieces, in a single transaction rather than a chain of them.
 *
 * @param address {@code D...} transparent address
 * @param amount  value in satoshi; must clear the 546-sat dust threshold, since
 *                nodes reject sub-dust outputs as nonstandard
 */
public record Recipient(String address, long amount) {

    public Recipient {
        if (address == null || address.isBlank()) {
            throw new IllegalArgumentException("recipient address is required");
        }
        if (amount < CoinSelector.MIN_CHANGE) {
            throw new IllegalArgumentException("recipient amount " + amount
                    + " sat is below the dust threshold (" + CoinSelector.MIN_CHANGE
                    + " sat): " + address);
        }
    }
}
