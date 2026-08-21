package dev.jpivx.wallet.tx;

import org.junit.jupiter.api.Test;
import org.bouncycastle.util.encoders.Hex;

import dev.jpivx.wallet.core.FeeEstimator;
import dev.jpivx.wallet.crypto.BIP39Service;
import dev.jpivx.wallet.crypto.PivxAddress;
import dev.jpivx.wallet.crypto.TransparentKeys;
import dev.jpivx.wallet.core.Utxo;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Port of the transparent-builder tests from {@code tests/integration.rs}:
 * {@code transparent_to_transparent_tx_needs_no_prover},
 * {@code raw_transparent_from_utxos_signs_with_custom_hd_index},
 * {@code raw_transparent_from_utxos_full_amount_has_no_change_output},
 * {@code raw_transparent_from_utxos_empty_utxos_fails},
 * {@code raw_transparent_from_utxos_insufficient_balance_fails},
 * {@code transparent_to_shield_requires_prover}.
 *
 * <p>Golden txhex vectors were captured from the Rust kit via a temporary
 * {@code print_txhex_for_cross_verify} test run with {@code --nocapture}; the
 * Java builder must reproduce them byte-for-byte (both libraries use RFC6979
 * deterministic nonces, so the signature is deterministic).
 */
class RawTransparentBuilderTest {

    static final String TEST_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    private static byte[] seed() {
        return BIP39Service.toSeed(BIP39Service.parse(TEST_MNEMONIC));
    }

    private static Utxo utxo(String txidChar, int vout, long amount) {
        return new Utxo(txidChar.repeat(64), vout, amount, "", 5_000_000);
    }

    private static String ownAddress() {
        return TransparentKeys.getTransparentAddress(TEST_MNEMONIC);
    }

    // ---- golden vectors captured from Rust (print_txhex_for_cross_verify) ----

    /** Case A: wallet-aware, 1 UTXO of 5 PIV, send 1 PIV to own address. */
    static final String GOLDEN_CASEA_TXHEX =
            "0100000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    + "000000006b483045022100cb5371ec45a7912468122ec5f65a3793440e17fd9fb68b9cb55b3e4a753dc35d"
                    + "022005d86fa18caffea82d548795dcb9bc5df11b1d1ef53a326a51f1a164574597ed01210399d319ee6de45a113e1084b79ade7609616f608049916b7dff2a8cef8497903affffffff"
                    + "0200e1f505000000001976a914cca48133ff2474bf4d9922e0cd8f72057fe47e5a88ac"
                    + "187bd717000000001976a914cca48133ff2474bf4d9922e0cd8f72057fe47e5a88ac00000000";

    /** Case B: from_utxos, HD index 5, 1 UTXO of 1 PIV at "b"*64 vout 1, send 0.5 PIV. */
    static final String GOLDEN_CASEB_TXHEX =
            "0100000001bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    + "010000006a47304402205456a11277db55c87879f40f412f6648db2fedf2b39280468ea5f7638e4e4b82"
                    + "02204cdf5b92b66db36d720f9ded64a339bb841318683402b82754c931ddedf34879012102b26ad0a2b53b9eee2e6c057722d2bdef654c6ef9e3a3073d56466cf31b6b1698ffffffff"
                    + "0280f0fa02000000001976a914cca48133ff2474bf4d9922e0cd8f72057fe47e5a88ac"
                    + "98e7fa02000000001976a914bea0e988645571705509becb6b8257dc93f0d72188ac00000000";

    /** Case C: from_utxos, HD index 3, full-amount (no change), 1 UTXO of 1 PIV at "c"*64 vout 0. */
    static final String GOLDEN_CASEC_TXHEX =
            "0100000001cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                    + "000000006a4730440220552bca6acfa670dfcadb16c0535dbee269fb60b75cee720b9c0fe4a6aa1d114e"
                    + "02204bbec2ec097d6b3dc94b2efa5ac3d27281dabbf3073c75ae0e2928915404dd7d012102bec9016fba7c120ea5a1b9859dcb668ba9d0b2b1691e0160a9a96530b440af3dffffffff"
                    + "0118d8f505000000001976a914cca48133ff2474bf4d9922e0cd8f72057fe47e5a88ac00000000";

    // ---- transparent_to_transparent_tx_needs_no_prover (Case A) ----

    @Test
    void transparentToTransparentTxNeedsNoProver() {
        List<Utxo> utxos = List.of(utxo("a", 0, 500_000_000));
        String dest = ownAddress();

        TransparentTransactionResult r = RawTransparentBuilder.createRawTransparentTransaction(
                utxos, seed(), dest, 100_000_000);

        assertFalse(r.txhex().isEmpty());
        assertEquals(100_000_000L, r.amount());
        assertEquals(1, r.spent().size());

        byte[] txBytes = Hex.decode(r.txhex());
        // Raw v1 tx: version bytes 0x01 0x00 0x00 0x00.
        assertArrayEquals(new byte[]{0x01, 0x00, 0x00, 0x00},
                Arrays.copyOfRange(txBytes, 0, 4));
    }

    @Test
    void caseATxhexMatchesRustGoldenVector() {
        List<Utxo> utxos = List.of(utxo("a", 0, 500_000_000));
        TransparentTransactionResult r = RawTransparentBuilder.createRawTransparentTransaction(
                utxos, seed(), ownAddress(), 100_000_000);
        assertEquals(GOLDEN_CASEA_TXHEX, r.txhex(),
                "Case A txhex must be byte-identical to the Rust kit's output");
    }

    // ---- raw_transparent_from_utxos_signs_with_custom_hd_index (Case B) ----

    @Test
    void rawTransparentFromUtxosSignsWithCustomHdIndex() {
        List<Utxo> utxos = List.of(utxo("b", 1, 100_000_000));
        String to = ownAddress();

        TransparentTransactionResult r = RawTransparentBuilder.createRawTransparentTransactionFromUtxos(
                seed(), 0, 5, utxos, to, 50_000_000);

        assertFalse(r.txhex().isEmpty());
        assertEquals(50_000_000L, r.amount());
        assertEquals(1, r.spent().size());
        assertEquals("b".repeat(64), r.spent().get(0).txid());
        assertEquals(1, r.spent().get(0).vout());

        // The change output must pay back to the HD-indexed source address.
        TransparentKeys.TransparentKey fromKey =
                TransparentKeys.transparentKeyFromBip39Seed(seed(), 0, 5);
        byte[] fromScript;
        try {
            fromScript = PivxAddress.addressToP2pkhScript(fromKey.address());
        } catch (Exception e) {
            fromScript = new byte[0];
        }
        byte[] txBytes = Hex.decode(r.txhex());
        assertTrue(windowsContains(txBytes, fromScript),
                "change output should pay back to the HD-indexed source address");
    }

    @Test
    void caseBTxhexMatchesRustGoldenVector() {
        List<Utxo> utxos = List.of(utxo("b", 1, 100_000_000));
        TransparentTransactionResult r = RawTransparentBuilder.createRawTransparentTransactionFromUtxos(
                seed(), 0, 5, utxos, ownAddress(), 50_000_000);
        assertEquals(GOLDEN_CASEB_TXHEX, r.txhex(),
                "Case B txhex must be byte-identical to the Rust kit's output");
    }

    // ---- raw_transparent_from_utxos_full_amount_has_no_change_output (Case C) ----

    @Test
    void rawTransparentFromUtxosFullAmountHasNoChangeOutput() {
        List<Utxo> utxos = List.of(utxo("c", 0, 100_000_000));
        long fee = FeeEstimator.estimateRawTransparentFee(1, 2);

        TransparentTransactionResult r = RawTransparentBuilder.createRawTransparentTransactionFromUtxos(
                seed(), 0, 3, utxos, ownAddress(), 100_000_000 - fee);

        assertEquals(1, r.spent().size());
        assertEquals(fee, r.fee());
    }

    @Test
    void caseCTxhexMatchesRustGoldenVector() {
        List<Utxo> utxos = List.of(utxo("c", 0, 100_000_000));
        long fee = FeeEstimator.estimateRawTransparentFee(1, 2);
        TransparentTransactionResult r = RawTransparentBuilder.createRawTransparentTransactionFromUtxos(
                seed(), 0, 3, utxos, ownAddress(), 100_000_000 - fee);
        assertEquals(GOLDEN_CASEC_TXHEX, r.txhex(),
                "Case C txhex must be byte-identical to the Rust kit's output");
    }

    // ---- raw_transparent_from_utxos_empty_utxos_fails ----

    @Test
    void rawTransparentFromUtxosEmptyUtxosFails() {
        assertThrows(IllegalArgumentException.class,
                () -> RawTransparentBuilder.createRawTransparentTransactionFromUtxos(
                        seed(), 0, 0, new ArrayList<>(), ownAddress(), 100));
    }

    // ---- raw_transparent_from_utxos_insufficient_balance_fails ----

    @Test
    void rawTransparentFromUtxosInsufficientBalanceFails() {
        List<Utxo> utxos = List.of(utxo("d", 0, 1_000));
        assertThrows(IllegalArgumentException.class,
                () -> RawTransparentBuilder.createRawTransparentTransactionFromUtxos(
                        seed(), 0, 1, utxos, ownAddress(), 100_000_000));
    }

    // ---- transparent_to_shield_requires_prover (deferred in transparent-only) ----

    @Test
    void transparentToShieldRequiresProver() {
        List<Utxo> utxos = List.of(utxo("a", 0, 500_000_000));
        // A shield-shaped destination — the builder must reject it (no Sapling prover in this build).
        String shieldDest = "ps1invalidbutstartswithps";
        assertThrows(IllegalArgumentException.class,
                () -> RawTransparentBuilder.createRawTransparentTransaction(
                        utxos, seed(), shieldDest, 100_000_000));
        assertThrows(IllegalArgumentException.class,
                () -> RawTransparentBuilder.createRawTransparentTransactionFromUtxos(
                        seed(), 0, 0, utxos, shieldDest, 100_000_000));
    }

    // ---- amount validation & dust handling ----

    @Test
    void nonPositiveAmountsAreRejected() {
        List<Utxo> utxos = List.of(utxo("a", 0, 500_000_000));
        for (long bad : new long[]{0, -1, -100_000_000}) {
            assertThrows(IllegalArgumentException.class,
                    () -> RawTransparentBuilder.createRawTransparentTransaction(
                            utxos, seed(), ownAddress(), bad));
            assertThrows(IllegalArgumentException.class,
                    () -> RawTransparentBuilder.createRawTransparentTransactionFromUtxos(
                            seed(), 0, 0, utxos, ownAddress(), bad));
            assertThrows(IllegalArgumentException.class,
                    () -> RawTransparentBuilder.createRawTransparentTransactionMultiIndex(
                            utxos, seed(), ownAddress(), bad));
        }
    }

    @Test
    void duplicateOutpointsAreRejected() {
        // The same (txid, vout) twice — e.g. a caller merging overlapping UTXO
        // queries — would produce a consensus-invalid tx
        // (bad-txns-inputs-duplicate), so the builder must refuse to sign it.
        List<Utxo> utxos = List.of(utxo("a", 0, 100_000_000), utxo("a", 0, 100_000_000));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> RawTransparentBuilder.createRawTransparentTransactionFromUtxos(
                        seed(), 0, 0, utxos, ownAddress(), 150_000_000));
        assertTrue(e.getMessage().contains("duplicate outpoint"), e.getMessage());
    }

    @Test
    void subDustAmountsAreRejectedOnEveryEntryPoint() {
        // The invariant the batch path's Recipient enforces: one sub-dust
        // output makes the whole transaction unrelayable. The legacy
        // single-recipient entry points must agree.
        List<Utxo> utxos = List.of(utxo("a", 0, 500_000_000));
        for (long bad : new long[]{1, 100, 545}) {
            assertThrows(IllegalArgumentException.class,
                    () -> RawTransparentBuilder.createRawTransparentTransaction(
                            utxos, seed(), ownAddress(), bad));
            assertThrows(IllegalArgumentException.class,
                    () -> RawTransparentBuilder.createRawTransparentTransactionFromUtxos(
                            seed(), 0, 0, utxos, ownAddress(), bad));
            assertThrows(IllegalArgumentException.class,
                    () -> RawTransparentBuilder.createRawTransparentTransactionMultiIndex(
                            utxos, seed(), ownAddress(), bad));
        }
    }

    @Test
    void nearMaxAmountFailsInsteadOfOverflowing() {
        // amount + fee used to wrap negative, pass the sufficiency check, and
        // produce a signed tx with garbage output values.
        List<Utxo> utxos = List.of(utxo("a", 0, 500_000_000));
        assertThrows(RuntimeException.class,
                () -> RawTransparentBuilder.createRawTransparentTransactionFromUtxos(
                        seed(), 0, 0, utxos, ownAddress(), Long.MAX_VALUE - 1000));
        assertThrows(RuntimeException.class,
                () -> RawTransparentBuilder.createRawTransparentTransaction(
                        utxos, seed(), ownAddress(), Long.MAX_VALUE - 1000));
    }

    @Test
    void subDustChangeIsFoldedIntoFee() {
        // One UTXO whose surplus over amount+fee is below the 546-sat dust
        // threshold: the tx must have ONE output and report the dust as fee.
        long fee2 = CoinSelector.estimateFee(1, 2);
        long amount = 100_000_000;
        long dust = 100; // < MIN_CHANGE
        List<Utxo> utxos = List.of(utxo("a", 0, amount + fee2 + dust));
        TransparentTransactionResult r =
                RawTransparentBuilder.createRawTransparentTransactionFromUtxos(
                        seed(), 0, 0, utxos, ownAddress(), amount);
        assertEquals(fee2 + dust, r.fee(), "dust change must be donated to the fee");
        // No change output: a 100-sat output value must not appear in the tx.
        byte[] tx = dev.jpivx.wallet.internal.ByteUtil.fromHex(r.txhex());
        byte[] dustLe = new byte[]{100, 0, 0, 0, 0, 0, 0, 0};
        org.junit.jupiter.api.Assertions.assertFalse(windowsContains(tx, dustLe),
                "sub-dust change output must not be serialized");
    }

    // ---- createRawTransparentTransaction insufficient balance ----

    @Test
    void createRawTransparentTransactionInsufficientBalanceFails() {
        List<Utxo> utxos = List.of(utxo("e", 0, 1_000));
        assertThrows(IllegalArgumentException.class,
                () -> RawTransparentBuilder.createRawTransparentTransaction(
                        utxos, seed(), ownAddress(), 100_000_000));
    }

    @Test
    void createRawTransparentTransactionSelectsLargestFirst() {
        // Two UTXOs: small + large. The selector should pick the large one first
        // and only add the small one if the large alone can't cover amount+fee.
        // Both txids are valid lowercase hex.
        List<Utxo> utxos = List.of(
                utxo("a", 0, 100_000_000),  // 1 PIV
                utxo("b", 0, 500_000_000)   // 5 PIV
        );
        // Send 1 PIV — the 5-PIV UTXO alone covers it (1 PIV + ~few hundred sat fee).
        TransparentTransactionResult r = RawTransparentBuilder.createRawTransparentTransaction(
                utxos, seed(), ownAddress(), 100_000_000);
        assertEquals(1, r.spent().size(), "should select only the largest UTXO");
        assertEquals("b".repeat(64), r.spent().get(0).txid());
    }

    // ---- helper ----

    private static boolean windowsContains(byte[] haystack, byte[] needle) {
        if (needle.length == 0 || needle.length > haystack.length) {
            return false;
        }
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            boolean match = true;
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return true;
            }
        }
        return false;
    }
}
