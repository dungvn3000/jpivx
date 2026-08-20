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
import java.time.Duration;
import java.util.List;

import dev.jpivx.wallet.core.Utxo;

/**
 * Blockbook API v2 REST client.
 *
 * <p>Fetches the UTXO set for a transparent address via
 * {@code GET /api/v2/utxo/{address}} and parses the response through
 * {@link BlockbookParser}.
 */
public final class BlockbookClient {

    private final String baseUrl;
    private final HttpClient client;

    public BlockbookClient(String baseUrl) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    /**
     * Fetch confirmed unspent outputs for the given transparent address.
     *
     * @param address a {@code D...} PIVX transparent address
     * @return the parsed confirmed UTXO list (unconfirmed entries filtered out,
     *         duplicates by (txid, vout) removed)
     */
    public List<Utxo> getUtxos(String address) throws IOException, InterruptedException {
        return getUtxos(address, true, 0);
    }

    public List<Utxo> getUtxos(String address, boolean confirmedOnly)
            throws IOException, InterruptedException {
        return getUtxos(address, confirmedOnly, 0);
    }

    /**
     * Fetch unspent outputs for the given transparent address, tagging each
     * UTXO with the specified HD index.
     */
    public List<Utxo> getUtxos(String address, boolean confirmedOnly, int hdIndex)
            throws IOException, InterruptedException {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/v2/utxo/" + address))
                .header("Accept", "application/json")
                .timeout(Duration.ofSeconds(30))
                .GET()
                .build();

        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) {
            throw new IOException("Blockbook returned HTTP " + resp.statusCode()
                    + ": " + resp.body());
        }
        JsonArray raw;
        try {
            raw = JsonParser.array().from(resp.body());
        } catch (JsonParserException e) {
            throw new IOException("Blockbook returned an unparseable body: " + resp.body(), e);
        }
        return BlockbookParser.parseBlockbookUtxos(raw, confirmedOnly, hdIndex);
    }

    /**
     * Broadcast a signed transaction via the Blockbook {@code /api/v2/sendtx/}
     * endpoint. No authentication required.
     *
     * @param txhex the signed transaction as a lowercase hex string
     * @return the transaction id returned by the node
     * @throws IOException if the node rejects the transaction or the response is malformed
     */
    public String sendTransaction(String txhex) throws IOException, InterruptedException {
        // POST with the hex in the body: a GET would carry the whole tx in the
        // URL, which breaks on large (multi-KB) transactions once the URI
        // exceeds proxy/header limits.
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/v2/sendtx/"))
                .header("Accept", "application/json")
                .timeout(Duration.ofSeconds(30))
                .POST(HttpRequest.BodyPublishers.ofString(txhex))
                .build();

        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        // Blockbook reports rejections as JSON {"error": ...} (often with a 4xx
        // status); non-JSON bodies (proxy errors, HTML) would otherwise blow up
        // in the parser with a confusing error.
        JsonObject body;
        try {
            body = JsonParser.object().from(resp.body());
        } catch (JsonParserException e) {
            throw new IOException("Broadcast failed: HTTP " + resp.statusCode()
                    + ", unparseable body: " + resp.body(), e);
        }
        if (body.has("error") && !body.isNull("error")) {
            // The error is usually a string, but some deployments nest an
            // object; render those as JSON rather than as a Java map dump.
            Object err = body.get("error");
            throw new IOException("Broadcast error: "
                    + (err instanceof String s ? s : JsonWriter.string(err)));
        }
        if (resp.statusCode() != 200) {
            throw new IOException("Broadcast failed: HTTP " + resp.statusCode()
                    + ": " + resp.body());
        }
        return body.getString("result", "");
    }
}
