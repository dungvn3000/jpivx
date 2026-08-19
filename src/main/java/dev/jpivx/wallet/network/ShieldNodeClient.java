package dev.jpivx.wallet.network;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Client for the PIVX Core node REST interface (the {@code -rest} endpoints,
 * as fronted by {@code https://rpc.pivxla.bz/mainnet}).
 *
 * <p>Only the endpoints needed for shield sync:
 * <ul>
 *   <li>{@code GET /getblockcount} — chain tip height.</li>
 *   <li>{@code GET /getshielddata?startBlock=N} — binary length-prefixed
 *       shield stream (see {@code dev.jpivx.wallet.shield.ShieldStreamParser}).</li>
 * </ul>
 *
 * <p>Responses are streamed ({@code ofInputStream}) so multi-megabyte shield
 * history never lands fully in memory.
 */
public final class ShieldNodeClient {

    private final String baseUrl;
    private final HttpClient http;

    public ShieldNodeClient(String baseUrl) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(30))
                .build();
    }

    /** Chain tip block height. */
    public int getBlockCount() throws IOException, InterruptedException {
        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl + "/getblockcount"))
                .timeout(Duration.ofSeconds(30))
                .GET()
                .build();
        HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (res.statusCode() != 200) {
            throw new IOException("getblockcount failed: HTTP " + res.statusCode());
        }
        return Integer.parseInt(res.body().trim());
    }

    /**
     * Open the binary shield stream from {@code startBlock} (inclusive) to
     * the chain tip. Caller MUST close the returned stream (try-with-resources).
     */
    public InputStream getShieldData(int startBlock) throws IOException, InterruptedException {
        // Response timeout covers time-to-headers only; the streamed body can
        // legitimately take much longer and is not cut off by this.
        HttpRequest req = HttpRequest.newBuilder(
                        URI.create(baseUrl + "/getshielddata?startBlock=" + startBlock))
                .timeout(Duration.ofSeconds(60))
                .GET()
                .build();
        HttpResponse<InputStream> res = http.send(req, HttpResponse.BodyHandlers.ofInputStream());
        if (res.statusCode() != 200) {
            res.body().close();
            throw new IOException("getshielddata failed: HTTP " + res.statusCode());
        }
        return res.body();
    }
}
