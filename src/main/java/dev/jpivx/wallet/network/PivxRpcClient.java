package dev.jpivx.wallet.network;

import com.grack.nanojson.JsonArray;
import com.grack.nanojson.JsonObject;
import com.grack.nanojson.JsonParser;
import com.grack.nanojson.JsonParserException;
import com.grack.nanojson.JsonWriter;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;

/**
 * Minimal PIVX Core JSON-RPC 2.0 client.
 *
 * <p>Supports {@code sendrawtransaction} and {@code getblockcount} — the two
 * calls the CLI needs for broadcasting and birthday-height lookup.
 */
public final class PivxRpcClient {

    private final String rpcUrl;
    private final String authHeader;
    private final HttpClient client;

    public PivxRpcClient(String rpcUrl, String rpcUser, String rpcPass) {
        this.rpcUrl = rpcUrl.endsWith("/") ? rpcUrl.substring(0, rpcUrl.length() - 1) : rpcUrl;
        this.authHeader = "Basic " + Base64.getEncoder()
                .encodeToString((rpcUser + ":" + rpcPass).getBytes(StandardCharsets.UTF_8));
        this.client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    /**
     * Broadcast a raw transaction.
     *
     * @param txhex the signed transaction hex
     * @return the transaction id
     * @throws IOException if the node rejects the transaction
     */
    public String sendRawTransaction(String txhex) throws IOException, InterruptedException {
        JsonObject body = call("sendrawtransaction", txhex);
        if (!body.isString("result")) {
            throw new IOException("RPC response carries no txid: " + JsonWriter.string(body));
        }
        return body.getString("result");
    }

    /**
     * Get the current chain tip height.
     */
    public int getBlockCount() throws IOException, InterruptedException {
        JsonObject body = call("getblockcount");
        // Never fall back to a default here: a silent 0 would restart a shield
        // sync from the genesis block.
        if (!body.isNumber("result")) {
            throw new IOException("RPC response carries no block count: " + JsonWriter.string(body));
        }
        return body.getInt("result");
    }

    /** Send one JSON-RPC call and return the full response object (errors raised as IOException). */
    private JsonObject call(String method, String... params) throws IOException, InterruptedException {
        JsonObject request = new JsonObject();
        request.put("jsonrpc", "2.0");
        request.put("method", method);
        JsonArray paramsArray = new JsonArray();
        for (String p : params) {
            paramsArray.add(p);
        }
        request.put("params", paramsArray);
        request.put("id", 1);

        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(rpcUrl))
                .header("Content-Type", "application/json")
                .header("Authorization", authHeader)
                .POST(HttpRequest.BodyPublishers.ofString(JsonWriter.string(request)))
                .timeout(Duration.ofSeconds(30))
                .build();

        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        JsonObject body;
        try {
            body = JsonParser.object().from(resp.body());
        } catch (JsonParserException e) {
            throw new IOException("RPC returned an unparseable body (HTTP "
                    + resp.statusCode() + "): " + resp.body(), e);
        }

        if (body.has("error") && !body.isNull("error")) {
            JsonObject err = body.getObject("error", new JsonObject());
            throw new IOException("RPC error " + err.getInt("code", 0)
                    + ": " + err.getString("message", ""));
        }
        return body;
    }
}
