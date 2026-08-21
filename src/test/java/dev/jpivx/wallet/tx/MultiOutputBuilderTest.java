package dev.jpivx.wallet.tx;

import dev.jpivx.wallet.core.FeeEstimator;
import dev.jpivx.wallet.core.Utxo;
import dev.jpivx.wallet.crypto.BIP39Service;
import dev.jpivx.wallet.crypto.PivxAddress;
import dev.jpivx.wallet.crypto.TransparentKeys;
import dev.jpivx.wallet.internal.ByteUtil;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Multi-recipient transparent sends: paying several destinations, and splitting
 * one UTXO into many spendable pieces, in a single transaction.
 */
class MultiOutputBuilderTest {

    private static final String MNEMONIC =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    private static final String OWN = "DPo9TNvPwy2ZfmVM3CRCxbBvh6NojguWXJ";
    private static final String OTHER = "D7qd6fwfh3T622wYFi5xLjBtwhYcKBqAMa";

    private static byte[] seed() {
        return BIP39Service.toSeed(BIP39Service.parse(MNEMONIC));
    }

    private static Utxo utxo(long sat, String txid) {
        String script = ByteUtil.toHex(PivxAddress.addressToP2pkhScript(OWN));
        return new Utxo(txid, 0, sat, script, 5_000_000, 0);
    }

    /** Minimal output parser: value + script per output, after inputs. */
    private record Output(long value, String scriptHex) {}

    private static List<Output> outputsOf(String txhex) {
        byte[] tx = ByteUtil.fromHex(txhex);
        int p = 4;                          // version
        int inputs = tx[p++] & 0xff;        // varint < 0xfd for these tests
        for (int i = 0; i < inputs; i++) {
            p += 36;                        // txid + vout
            int scriptLen = tx[p++] & 0xff;
            p += scriptLen + 4;             // scriptSig + sequence
        }
        int count = tx[p++] & 0xff;
        List<Output> outputs = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            long value = 0;
            for (int b = 0; b < 8; b++) {
                value |= (long) (tx[p + b] & 0xff) << (8 * b);
            }
            p += 8;
            int len = tx[p++] & 0xff;
            outputs.add(new Output(value, ByteUtil.toHex(java.util.Arrays.copyOfRange(tx, p, p + len))));
            p += len;
        }
        return outputs;
    }

    @Test
    void oneRecipientMatchesTheSingleRecipientBuilderByteForByte() {
        byte[] seed = seed();
        List<Utxo> utxos = List.of(utxo(500_000_000L, "a".repeat(64)));

        TransparentTransactionResult classic = RawTransparentBuilder
                .createRawTransparentTransactionMultiIndex(utxos, seed, OTHER, 100_000_000L);
        TransparentTransactionResult viaList = RawTransparentBuilder
                .createRawTransparentTransaction(utxos, seed, List.of(new Recipient(OTHER, 100_000_000L)));

        assertEquals(classic.txhex(), viaList.txhex(),
                "the generalised path must not change the existing one-recipient shape");
        assertEquals(classic.fee(), viaList.fee());
    }

    @Test
    void splittingOneUtxoProducesOnePieceEachPlusChange() {
        byte[] seed = seed();
        List<Utxo> utxos = List.of(utxo(1_000_000_000L, "b".repeat(64)));
        List<Recipient> pieces = RawTransparentBuilder.split(OWN, 400_000_000L, 4);

        TransparentTransactionResult tx =
                RawTransparentBuilder.createRawTransparentTransaction(utxos, seed, pieces);

        List<Output> outputs = outputsOf(tx.txhex());
        assertEquals(5, outputs.size(), "four pieces plus change");
        for (int i = 0; i < 4; i++) {
            assertEquals(100_000_000L, outputs.get(i).value());
        }
        assertEquals(400_000_000L, tx.amount(), "amount() counts recipients, not change");
        assertEquals(FeeEstimator.estimateRawTransparentFee(1, 5), tx.fee());
        assertEquals(1_000_000_000L, outputs.stream().mapToLong(Output::value).sum() + tx.fee(),
                "inputs = outputs + fee");
    }

    @Test
    void anUnevenSplitPutsTheRemainderInTheLastPiece() {
        List<Recipient> pieces = RawTransparentBuilder.split(OWN, 1_000_000_007L, 3);

        assertEquals(3, pieces.size());
        assertEquals(333_333_335L, pieces.get(0).amount());
        assertEquals(333_333_335L, pieces.get(1).amount());
        assertEquals(333_333_337L, pieces.get(2).amount());
        assertEquals(1_000_000_007L, pieces.stream().mapToLong(Recipient::amount).sum());
    }

    @Test
    void everyRecipientGetsItsOwnScript() {
        byte[] seed = seed();
        List<Utxo> utxos = List.of(utxo(1_000_000_000L, "c".repeat(64)));

        TransparentTransactionResult tx = RawTransparentBuilder.createRawTransparentTransaction(
                utxos, seed, List.of(new Recipient(OWN, 100_000_000L),
                        new Recipient(OTHER, 200_000_000L)));

        List<Output> outputs = outputsOf(tx.txhex());
        assertEquals(3, outputs.size());
        assertEquals(ByteUtil.toHex(PivxAddress.addressToP2pkhScript(OWN)), outputs.get(0).scriptHex());
        assertEquals(ByteUtil.toHex(PivxAddress.addressToP2pkhScript(OTHER)), outputs.get(1).scriptHex());
        // Change returns to the address that owns the inputs.
        String changeScript = ByteUtil.toHex(PivxAddress.addressToP2pkhScript(
                TransparentKeys.transparentKeyFromBip39Seed(seed, 0, 0).address()));
        assertEquals(changeScript, outputs.get(2).scriptHex());
        assertEquals(300_000_000L, tx.amount());
    }

    @Test
    void subDustAndShieldAndEmptyRecipientsAreRejected() {
        byte[] seed = seed();
        List<Utxo> utxos = List.of(utxo(1_000_000_000L, "d".repeat(64)));

        assertThrows(IllegalArgumentException.class, () -> new Recipient(OWN, 545L),
                "a sub-dust output makes the whole transaction nonstandard");
        assertThrows(IllegalArgumentException.class,
                () -> RawTransparentBuilder.createRawTransparentTransaction(utxos, seed, List.of()));
        assertThrows(IllegalArgumentException.class,
                () -> RawTransparentBuilder.createRawTransparentTransaction(utxos, seed,
                        List.of(new Recipient("ps124f3dxh", 100_000_000L))));
        assertThrows(IllegalArgumentException.class,
                () -> RawTransparentBuilder.split(OWN, 1000L, 4));
    }

    @Test
    void aTransactionOverTheStandardnessSizeLimitIsRejected() {
        byte[] seed = seed();
        // 3,000 dust-minimum pieces serialize to ~102KB of outputs alone —
        // consensus-valid, but no default-policy node would relay it.
        List<Recipient> pieces = RawTransparentBuilder.split(OWN, 3_000L * 546L, 3_000);
        List<Utxo> utxos = List.of(utxo(5_000_000L, "f".repeat(64)));

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> RawTransparentBuilder.createRawTransparentTransaction(utxos, seed, pieces));
        assertTrue(e.getMessage().contains("standardness"), e.getMessage());
    }

    @Test
    void insufficientBalanceCountsEveryOutputInTheFee() {
        byte[] seed = seed();
        // Exactly the recipient total, so the fee for 4 outputs cannot be covered.
        List<Utxo> utxos = List.of(utxo(300_000_000L, "e".repeat(64)));

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> RawTransparentBuilder.createRawTransparentTransaction(utxos, seed,
                        List.of(new Recipient(OWN, 100_000_000L), new Recipient(OWN, 100_000_000L),
                                new Recipient(OTHER, 100_000_000L))));
        assertTrue(e.getMessage().contains("Insufficient"), e.getMessage());
    }
}
