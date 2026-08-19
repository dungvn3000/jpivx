package dev.jpivx.wallet.shield;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;

/**
 * Sapling Groth16 proving parameters ({@code sapling-output.params},
 * {@code sapling-spend.params}) — download, cache, and integrity check.
 *
 * <p>The hashes pinned here are the SAME SHA256 pins as the Rust kit
 * ({@code params.rs}) — which are the canonical Zcash mainnet Sapling
 * parameter hashes. The native side ALSO verifies them
 * ({@code verify_and_load_params}) right before proving, so a corrupted
 * cache file can never produce an invalid proof.
 *
 * <p>Default cache dir: {@code ~/.pivx-wallet/params/} (override with
 * {@code -Djpivx.sapling.params=}). Default mirror:
 * {@code https://pivxla.bz} (derived from the default node REST URL by
 * stripping the {@code rpc.} host prefix and all path segments, exactly like
 * MyPIVXWallet).
 */
public final class SaplingParams {

    /** Kit pin: SHA256 of sapling-output.params (3.6 MB). */
    public static final String OUTPUT_PARAMS_SHA256 =
            "2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4";

    /** Kit pin: SHA256 of sapling-spend.params (~46 MB). */
    public static final String SPEND_PARAMS_SHA256 =
            "8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13";

    public static final String OUTPUT_PARAMS_FILE = "sapling-output.params";
    public static final String SPEND_PARAMS_FILE = "sapling-spend.params";

    /** Default params mirror (path-free host). */
    public static final String PARAMS_BASE_URL = "https://pivxla.bz";

    /** System property overriding {@link #defaultDir()}. */
    public static final String DIR_PROPERTY = "jpivx.sapling.params";

    private final Path dir;
    private final HttpClient http;

    public SaplingParams(Path dir) {
        this.dir = dir;
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(30))
                .build();
    }

    /** Default params dir: {@code $jpivx.sapling.params} or {@code ~/.pivx-wallet/params}. */
    public static Path defaultDir() {
        String override = System.getProperty(DIR_PROPERTY);
        if (override != null && !override.isBlank()) {
            return Path.of(override);
        }
        return Path.of(System.getProperty("user.home"), ".pivx-wallet", "params");
    }

    public Path spendPath() {
        return dir.resolve(SPEND_PARAMS_FILE);
    }

    public Path outputPath() {
        return dir.resolve(OUTPUT_PARAMS_FILE);
    }

    /** True when both files exist AND hash-match the pins. */
    public boolean present() {
        return hashMatches(outputPath(), OUTPUT_PARAMS_SHA256)
                && hashMatches(spendPath(), SPEND_PARAMS_SHA256);
    }

    /**
     * Ensure both params are cached under {@link #dir()}. Missing or
     * hash-mismatched files are (re)downloaded from {@code paramsBaseUrl},
     * verified against the SHA256 pins, and renamed atomically.
     *
     * @param paramsBaseUrl path-free HTTPS base, e.g. {@link #PARAMS_BASE_URL}
     * @param progressMegabytes print a progress dot every N MB to stderr (0 = silent)
     */
    public void ensureLoaded(String paramsBaseUrl, int progressMegabytes) throws IOException {
        Files.createDirectories(dir);
        ensureOne(OUTPUT_PARAMS_FILE, OUTPUT_PARAMS_SHA256, paramsBaseUrl, progressMegabytes);
        ensureOne(SPEND_PARAMS_FILE, SPEND_PARAMS_SHA256, paramsBaseUrl, progressMegabytes);
    }

    public Path dir() {
        return dir;
    }

    /**
     * Derive the params mirror from a node REST URL the way MyPIVXWallet
     * does: drop the {@code rpc.}/{@code rpc2.} host prefix and ALL path
     * segments — {@code https://rpc.pivxla.bz/mainnet} → {@code https://pivxla.bz}.
     */
    public static String deriveParamsBaseUrl(String nodeRestUrl) {
        URI uri = URI.create(nodeRestUrl);
        String host = uri.getHost();
        if (host == null) {
            throw new IllegalArgumentException("node URL has no host: " + nodeRestUrl);
        }
        if (host.startsWith("rpc2.")) {
            host = host.substring("rpc2.".length());
        } else if (host.startsWith("rpc.")) {
            host = host.substring("rpc.".length());
        }
        int port = uri.getPort();
        return "https://" + host + (port < 0 ? "" : ":" + port);
    }

    // -------------------------------------------------------------------

    private void ensureOne(String fileName, String expectedSha256,
                           String paramsBaseUrl, int progressMegabytes) throws IOException {
        Path target = dir.resolve(fileName);
        if (hashMatches(target, expectedSha256)) {
            return;
        }
        if (progressMegabytes > 0) {
            System.err.println("Downloading " + fileName + " from " + paramsBaseUrl + " ...");
        }
        Path tmp = dir.resolve(fileName + ".download");
        try {
            download(paramsBaseUrl + "/" + fileName, tmp, progressMegabytes);
            Files.move(tmp, target,
                    StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            String actual = sha256Hex(target);
            if (!actual.equals(expectedSha256)) {
                Files.deleteIfExists(target);
                throw new IOException(fileName + " SHA256 mismatch after download: got "
                        + actual + ", expected " + expectedSha256 + " (deleted the file)");
            }
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    private void download(String url, Path target, int progressMegabytes) throws IOException {
        HttpRequest req = HttpRequest.newBuilder(URI.create(url)).GET().build();
        HttpResponse<InputStream> res;
        try {
            res = http.send(req, HttpResponse.BodyHandlers.ofInputStream());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted while downloading " + url, e);
        }
        if (res.statusCode() != 200) {
            res.body().close();
            throw new IOException("download failed: HTTP " + res.statusCode() + " for " + url);
        }
        long nextReport = (long) progressMegabytes * 1024 * 1024;
        long total = 0;
        try (InputStream in = res.body();
             var out = Files.newOutputStream(target)) {
            byte[] buf = new byte[256 * 1024];
            int n;
            while ((n = in.read(buf)) != -1) {
                out.write(buf, 0, n);
                total += n;
                if (progressMegabytes > 0 && total >= nextReport) {
                    System.err.printf("  %d MB...%n", total / (1024 * 1024));
                    nextReport += (long) progressMegabytes * 1024 * 1024;
                }
            }
        }
        if (progressMegabytes > 0) {
            System.err.printf("  done: %.1f MB%n", total / (1024.0 * 1024));
        }
    }

    private static boolean hashMatches(Path file, String expectedSha256) {
        try {
            return Files.exists(file) && sha256Hex(file).equals(expectedSha256);
        } catch (IOException e) {
            return false;
        }
    }

    /** Hex SHA256 of a file, streamed. */
    public static String sha256Hex(Path file) throws IOException {
        final MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
        try (InputStream in = Files.newInputStream(file)) {
            byte[] buf = new byte[1024 * 1024];
            int n;
            while ((n = in.read(buf)) != -1) {
                md.update(buf, 0, n);
            }
        }
        return HexFormat.of().formatHex(md.digest());
    }
}
