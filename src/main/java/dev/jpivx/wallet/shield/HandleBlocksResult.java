package dev.jpivx.wallet.shield;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;


/**
 * Output of the JNI {@code handle_blocks} bridge — mirrors
 * {@code sapling::sync::HandleBlocksResult} from the Rust kit.
 *
 * @param commitmentTree hex-encoded updated commitment tree
 * @param newNotes       notes newly discovered in this batch
 * @param updatedNotes   previously-known notes with advanced witnesses
 * @param nullifiers     nullifiers seen (potential spends of our notes)
 */
public record HandleBlocksResult(
        @JsonProperty("commitment_tree") String commitmentTree,
        @JsonProperty("new_notes") List<SerializedNote> newNotes,
        @JsonProperty("updated_notes") List<SerializedNote> updatedNotes,
        @JsonProperty("nullifiers") List<String> nullifiers) {}
