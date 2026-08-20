package dev.jpivx.wallet.shield;

import com.grack.nanojson.JsonArray;
import com.grack.nanojson.JsonObject;
import com.grack.nanojson.JsonParser;
import com.grack.nanojson.JsonParserException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/** Small JSON helpers shared by the shield bridge result types. */
final class ShieldJson {

    private ShieldJson() {
        throw new AssertionError("no instances");
    }

    /**
     * Parse a JSON object returned by the shield bridge, reporting failures as
     * {@link IOException}. The offending payload is deliberately left out of the
     * message: it carries note and witness data.
     */
    static JsonObject parseObject(String json) throws IOException {
        try {
            return JsonParser.object().from(json);
        } catch (JsonParserException e) {
            throw new IOException("Shield bridge returned malformed JSON: " + e.getMessage(), e);
        }
    }

    /** Read a JSON array of strings; {@code null} or non-string entries are skipped. */
    static List<String> stringList(JsonArray arr) {
        List<String> out = new ArrayList<>();
        if (arr == null) {
            return out;
        }
        for (int i = 0; i < arr.size(); i++) {
            String s = arr.getString(i);
            if (s != null) {
                out.add(s);
            }
        }
        return out;
    }
}
