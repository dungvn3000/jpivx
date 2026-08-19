package dev.jpivx.wallet.shield;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Output of the JNI {@code selectShieldNotes} bridge — mirrors
 * {@code sapling::builder::ShieldSelection} from the Rust kit.
 *
 * @param indexes positions into the input notes, in spend order
 * @param fee     exact fee the builder will charge for this selection
 * @param total   sum of selected note values (&ge; amount + fee)
 */
public record ShieldSelection(
        @JsonProperty("indexes") List<Long> indexes,
        @JsonProperty("fee") long fee,
        @JsonProperty("total") long total) {}
