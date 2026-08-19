package dev.jpivx.wallet.shield;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Output of the JNI {@code createShieldTransaction} bridge — mirrors
 * {@code sapling::builder::TransactionResult} from the Rust kit.
 *
 * @param txhex      signed transaction hex (broadcast-ready)
 * @param nullifiers nullifiers of the spent notes (remove from wallet)
 * @param amount     amount sent, in satoshi
 * @param fee        fee paid, in satoshi
 */
public record ShieldTxResult(
        @JsonProperty("txhex") String txhex,
        @JsonProperty("nullifiers") List<String> nullifiers,
        @JsonProperty("amount") long amount,
        @JsonProperty("fee") long fee) {}
