package dev.jpivx.wallet.network;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

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

    private static final ObjectMapper MAPPER = new ObjectMapper();

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
        JsonNode result = call("sendrawtransaction", txhex);
        return result.asString();
    }

    /**
     * Get the current chain tip height.
     */
    public int getBlockCount() throws IOException, InterruptedException {
        JsonNode result = call("getblockcount");
        return result.asInt();
    }

    private JsonNode call(String method, String... params) throws IOException, InterruptedException {
        ObjectNode request = MAPPER.createObjectNode();
        request.put("jsonrpc", "2.0");
        request.put("method", method);
        var paramsArray = request.putArray("params");
        for (String p : params) {
            paramsArray.add(p);
        }
        request.put("id", 1);

        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(rpcUrl))
                .header("Content-Type", "application/json")
                .header("Authorization", authHeader)
                .POST(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(request)))
                .timeout(Duration.ofSeconds(30))
                .build();

        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        // Jackson 3 reports parse failures as an unchecked JacksonException; keep
        // surfacing them as IOException so callers only have to handle one type.
        JsonNode body;
        try {
            body = MAPPER.readTree(resp.body());
        } catch (JacksonException e) {
            throw new IOException("RPC returned an unparseable body (HTTP "
                    + resp.statusCode() + "): " + resp.body(), e);
        }

        if (body.has("error") && !body.get("error").isNull()) {
            JsonNode err = body.get("error");
            throw new IOException("RPC error " + err.path("code").asInt()
                    + ": " + err.path("message").asString());
        }
        return body.get("result");
    }
}
