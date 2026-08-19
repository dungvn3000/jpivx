package dev.jpivx.wallet.shield;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SaplingParamsTest {

    @TempDir Path tmp;

    @Test
    void sha256HexMatchesKnownVector() throws Exception {
        Path f = tmp.resolve("x.bin");
        Files.writeString(f, "abc");
        // Well-known SHA256("abc").
        assertEquals(
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                SaplingParams.sha256Hex(f));
    }

    @Test
    void deriveParamsBaseUrlStripsRpcPrefixAndPath() {
        assertEquals("https://pivxla.bz",
                SaplingParams.deriveParamsBaseUrl("https://rpc.pivxla.bz/mainnet"));
        assertEquals("https://pivxla.bz",
                SaplingParams.deriveParamsBaseUrl("https://rpc2.pivxla.bz/mainnet"));
        // Non-prefixed hosts are kept as-is (custom node), port preserved.
        assertEquals("https://node.example.com",
                SaplingParams.deriveParamsBaseUrl("https://node.example.com/api"));
        assertEquals("https://node.example.com:8443",
                SaplingParams.deriveParamsBaseUrl("https://node.example.com:8443/api"));
    }

    @Test
    void presentIsFalseWhenFilesMissing() {
        SaplingParams params = new SaplingParams(tmp);
        assertFalse(params.present());
    }

    @Test
    void presentIsFalseWhenHashMismatch() throws Exception {
        SaplingParams params = new SaplingParams(tmp);
        Files.createDirectories(tmp);
        Files.writeString(params.spendPath(), "garbage");
        Files.writeString(params.outputPath(), "garbage");
        assertFalse(params.present(), "hash mismatch must not count as present");
    }

    @Test
    void pinnedHashesMatchTheRustKit() {
        // Mirror of pivx-wallet-kit params.rs (Zcash mainnet Sapling pins).
        assertEquals(64, SaplingParams.OUTPUT_PARAMS_SHA256.length());
        assertEquals(64, SaplingParams.SPEND_PARAMS_SHA256.length());
        assertTrue(SaplingParams.OUTPUT_PARAMS_SHA256.startsWith("2f0ebb"));
        assertTrue(SaplingParams.SPEND_PARAMS_SHA256.startsWith("8e48ff"));
    }
}
