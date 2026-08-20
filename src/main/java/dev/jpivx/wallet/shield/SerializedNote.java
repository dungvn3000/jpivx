package dev.jpivx.wallet.shield;

import com.fasterxml.jackson.annotation.JsonInclude;
import tools.jackson.databind.JsonNode;

/**
 * A serializable spendable Sapling note (mirrors {@code wallet::SerializedNote}).
 *
 * <p>In this transparent-only build, the {@code note} field is an opaque JSON
 * blob — the Sapling {@code Note} structure is only meaningful once the shield
 * FFI is wired in. The wallet stores and passes it back unmodified so the JSON
 * on disk stays byte-compatible with the Rust kit.
 *
 * @param note       Sapling Note serialized as JSON (opaque here)
 * @param witness    hex-encoded incremental witness
 * @param nullifier  hex-encoded nullifier
 * @param memo       optional memo text (may be null — serializes as JSON null, matching Rust's Option&lt;String&gt;)
 * @param height     block height when the note was received
 */
@JsonInclude(JsonInclude.Include.ALWAYS)
public record SerializedNote(JsonNode note, String witness, String nullifier,
                             String memo, int height) {}
