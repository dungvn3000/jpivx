package dev.jpivx.wallet.shield;

import com.grack.nanojson.JsonArray;
import com.grack.nanojson.JsonObject;

import java.util.ArrayList;
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
        List<Long> indexes,
        long fee,
        long total) {

    /** Parse the bridge's JSON result; a missing index array reads as empty. */
    public static ShieldSelection fromJson(JsonObject o) {
        List<Long> indexes = new ArrayList<>();
        JsonArray arr = o.getArray("indexes");
        if (arr != null) {
            for (int i = 0; i < arr.size(); i++) {
                indexes.add(arr.getLong(i, 0));
            }
        }
        return new ShieldSelection(indexes, o.getLong("fee", 0), o.getLong("total", 0));
    }
}
