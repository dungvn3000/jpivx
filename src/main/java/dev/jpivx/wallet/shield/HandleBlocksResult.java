package dev.jpivx.wallet.shield;

import com.grack.nanojson.JsonObject;

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
        String commitmentTree,
        List<SerializedNote> newNotes,
        List<SerializedNote> updatedNotes,
        List<String> nullifiers) {

    /** Parse the bridge's JSON result; missing arrays read as empty. */
    public static HandleBlocksResult fromJson(JsonObject o) {
        return new HandleBlocksResult(
                o.getString("commitment_tree", ""),
                SerializedNote.fromJsonArray(o.getArray("new_notes")),
                SerializedNote.fromJsonArray(o.getArray("updated_notes")),
                ShieldJson.stringList(o.getArray("nullifiers")));
    }
}
