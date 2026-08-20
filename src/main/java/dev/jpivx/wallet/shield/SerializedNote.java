package dev.jpivx.wallet.shield;

import com.grack.nanojson.JsonArray;
import com.grack.nanojson.JsonObject;

import java.util.ArrayList;
import java.util.List;

/**
 * A serializable spendable Sapling note (mirrors {@code wallet::SerializedNote}).
 *
 * <p>The {@code note} field is an opaque JSON object — the Sapling {@code Note}
 * structure is only meaningful to the shield FFI. The wallet stores and passes
 * it back unmodified so the JSON on disk stays byte-compatible with the Rust
 * kit; {@link JsonObject} is a {@code LinkedHashMap}, so key order survives the
 * round trip.
 *
 * @param note       Sapling Note serialized as JSON (opaque here)
 * @param witness    hex-encoded incremental witness
 * @param nullifier  hex-encoded nullifier
 * @param memo       optional memo text (may be null — serializes as JSON null, matching Rust's Option&lt;String&gt;)
 * @param height     block height when the note was received
 */
public record SerializedNote(JsonObject note, String witness, String nullifier,
                             String memo, int height) {

    /** Read the kit's JSON array of {@code SerializedNote}; non-object entries are skipped. */
    public static List<SerializedNote> fromJsonArray(JsonArray arr) {
        List<SerializedNote> out = new ArrayList<>();
        if (arr == null) {
            return out;
        }
        for (int i = 0; i < arr.size(); i++) {
            JsonObject o = arr.getObject(i);
            if (o != null) {
                out.add(fromJson(o));
            }
        }
        return out;
    }

    /** Write a list of notes as the kit's JSON array of {@code SerializedNote}. */
    public static JsonArray toJsonArray(List<SerializedNote> notes) {
        JsonArray arr = new JsonArray();
        for (SerializedNote n : notes) {
            arr.add(n.toJson());
        }
        return arr;
    }

    /** Read one note of the kit's {@code SerializedNote} JSON shape. */
    public static SerializedNote fromJson(JsonObject o) {
        return new SerializedNote(
                o.getObject("note", new JsonObject()),
                o.getString("witness", ""),
                o.getString("nullifier", ""),
                o.getString("memo", null),
                o.getInt("height", 0));
    }

    /**
     * Write the kit's {@code SerializedNote} JSON shape. All five fields are
     * always emitted — a null memo becomes JSON {@code null}, matching serde's
     * {@code Option<String>} — and in the Rust struct's field order.
     */
    public JsonObject toJson() {
        JsonObject o = new JsonObject();
        o.put("note", note);
        o.put("witness", witness);
        o.put("nullifier", nullifier);
        o.put("memo", memo);
        o.put("height", height);
        return o;
    }
}
