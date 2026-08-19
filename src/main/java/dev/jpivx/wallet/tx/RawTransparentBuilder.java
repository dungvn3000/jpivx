package dev.jpivx.wallet.tx;

import dev.jpivx.wallet.internal.ECKey;
import dev.jpivx.wallet.internal.Sha256Hash;
import dev.jpivx.wallet.internal.ByteUtil;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import dev.jpivx.wallet.core.FeeEstimator;
import dev.jpivx.wallet.core.VarInt;
import dev.jpivx.wallet.crypto.PivxAddress;
import dev.jpivx.wallet.crypto.TransparentKeys;
import dev.jpivx.wallet.core.Utxo;

/**
 * Raw v1 P2PKH transparent transaction builder (no Sapling machinery).
 *
 * <p>Port of {@code transparent::builder::create_raw_transparent_transaction[_from_utxos]}
 * from the Rust {@code pivx-wallet-kit}. PIVX nodes reject v3 txs that carry no
 * Sapling data, so pure transparent→transparent sends take this legacy v1 path
 * signed with ECDSA / SIGHASH_ALL. No Sapling prover is touched.
 *
 * <p>Shield destinations ({@code ps1...}) are rejected — they require the
 * Sapling prover, which is not available in this transparent-only build.
 */
public final class RawTransparentBuilder {

    private RawTransparentBuilder() {
        throw new AssertionError("no instances");
    }

    /** Error thrown when a shield destination is requested (deferred to the FFI phase). */
    public static final String SHIELD_DEST_ERROR =
            "Shield destination requires a Sapling prover (not available in transparent-only build) "
                    + "— use a D... transparent address instead";

    /**
     * Build a signed v1 P2PKH transaction spending a caller-supplied set of UTXOs
     * from a specific HD slot.
     *
     * <p>Single recipient, single source. Any leftover ({@code total - amount - fee})
     * becomes a change output back to the <em>source</em> address. Pass
     * {@code amount = total - fee} to get exactly one output with no change.
     *
     * @param bip39Seed   64-byte BIP39 seed
     * @param fromChange  HD change branch (0 = external, 1 = internal)
     * @param fromIndex   HD address index within the branch
     * @param utxos       the UTXOs to spend (all of them are spent)
     * @param toAddress   the recipient {@code D...} transparent address
     * @param amount      the value to send, in satoshis
     * @return the signed transaction result
     * @throws IllegalArgumentException if {@code toAddress} is a shield address,
     *         {@code utxos} is empty, or the UTXOs are insufficient
     * @throws ArithmeticException if the UTXO total overflows
     */
    public static TransparentTransactionResult createRawTransparentTransactionFromUtxos(
            byte[] bip39Seed, int fromChange, int fromIndex, List<Utxo> utxos,
            String toAddress, long amount) {
        requireTransparentDest(toAddress);
        requireValidAmount(amount);
        if (utxos.isEmpty()) {
            throw new IllegalArgumentException("No UTXOs provided");
        }

        TransparentKeys.TransparentKey own =
                TransparentKeys.transparentKeyFromBip39Seed(bip39Seed, fromChange, fromIndex);
        byte[] toScript = PivxAddress.addressToP2pkhScript(toAddress);
        byte[] ownScript = PivxAddress.addressToP2pkhScript(own.address());

        long total = 0L;
        for (Utxo u : utxos) {
            total = Math.addExact(total, u.amount());
        }

        long fee = FeeEstimator.estimateRawTransparentFee(utxos.size(), 2);
        if (total < Math.addExact(amount, fee)) {
            throw new IllegalArgumentException(
                    "Insufficient UTXOs. Have: " + total + " sat, need: " + amount + " sat + " + fee + " sat fee");
        }
        Selection sel = foldDustChange(utxos, fee, total - amount - fee);

        // Every input signs with the same key/script.
        TransparentKeys.TransparentKey[] inputKeys = new TransparentKeys.TransparentKey[utxos.size()];
        java.util.Arrays.fill(inputKeys, own);

        byte[] txBytes = buildAndSign(utxos, inputKeys, ownScript, toScript, amount, sel.change);
        return result(txBytes, utxos, amount, sel.fee);
    }

    /**
     * Build a signed v1 P2PKH transaction, automatically selecting UTXOs from
     * the provided list (BnB first, Knapsack fallback) until amount + fee is covered.
     *
     * <p>Signs with the wallet's default key at {@code m/44'/119'/0'/0/0}.
     *
     * @param utxos      available UTXOs (selection is performed on a copy)
     * @param bip39Seed  64-byte BIP39 seed
     * @param toAddress  the recipient {@code D...} transparent address
     * @param amount     the value to send, in satoshis
     * @return the signed transaction result
     * @throws IllegalArgumentException if {@code toAddress} is a shield address,
     *         no UTXOs are available, or the balance is insufficient
     */
    public static TransparentTransactionResult createRawTransparentTransaction(
            List<Utxo> utxos, byte[] bip39Seed, String toAddress, long amount) {
        requireTransparentDest(toAddress);
        requireValidAmount(amount);
        if (utxos.isEmpty()) {
            throw new IllegalArgumentException("No transparent UTXOs available");
        }

        TransparentKeys.TransparentKey own =
                TransparentKeys.transparentKeyFromBip39Seed(bip39Seed, 0, 0);
        byte[] toScript = PivxAddress.addressToP2pkhScript(toAddress);
        byte[] ownScript = PivxAddress.addressToP2pkhScript(own.address());

        Selection sel = selectWithFee(utxos, amount);

        TransparentKeys.TransparentKey[] inputKeys =
                new TransparentKeys.TransparentKey[sel.selected.size()];
        java.util.Arrays.fill(inputKeys, own);

        byte[] txBytes = buildAndSign(sel.selected, inputKeys, ownScript, toScript, amount, sel.change);
        return result(txBytes, sel.selected, amount, sel.fee);
    }

    /**
     * Build a signed v1 P2PKH transaction spending UTXOs that may belong to
     * <em>different</em> HD derivation indices. Each input is signed with the
     * private key at {@code m/44'/119'/0'/0/{utxo.hdIndex()}}. Change goes back
     * to the first input's HD index.
     *
     * @param utxos      available UTXOs (each tagged with {@code hdIndex})
     * @param bip39Seed  64-byte BIP39 seed
     * @param toAddress  the recipient {@code D...} transparent address
     * @param amount     the value to send, in satoshis
     * @return the signed transaction result
     */
    public static TransparentTransactionResult createRawTransparentTransactionMultiIndex(
            List<Utxo> utxos, byte[] bip39Seed, String toAddress, long amount) {
        return createRawTransparentTransactionMultiIndex(utxos, bip39Seed, toAddress, amount, 0);
    }

    /**
     * Variant of {@link #createRawTransparentTransactionMultiIndex(List, byte[], String, long)}
     * that signs every input on the given HD change branch
     * ({@code m/44'/119'/0'/{fromChange}/{utxo.hdIndex()}}). All supplied UTXOs
     * must belong to that single branch — {@link Utxo} does not carry a branch
     * field, so mixed-branch input sets are not supported.
     *
     * @param fromChange HD change branch (0 = external, 1 = internal)
     */
    public static TransparentTransactionResult createRawTransparentTransactionMultiIndex(
            List<Utxo> utxos, byte[] bip39Seed, String toAddress, long amount, int fromChange) {
        requireTransparentDest(toAddress);
        requireValidAmount(amount);
        if (utxos.isEmpty()) {
            throw new IllegalArgumentException("No transparent UTXOs available");
        }

        Selection sel = selectWithFee(utxos, amount);

        // Derive one key per unique hdIndex in the selection.
        Map<Integer, TransparentKeys.TransparentKey> keyCache = new HashMap<>();
        TransparentKeys.TransparentKey[] inputKeys =
                new TransparentKeys.TransparentKey[sel.selected.size()];
        for (int i = 0; i < sel.selected.size(); i++) {
            inputKeys[i] = keyCache.computeIfAbsent(sel.selected.get(i).hdIndex(), idx ->
                    TransparentKeys.transparentKeyFromBip39Seed(bip39Seed, fromChange, idx));
        }

        byte[] toScript = PivxAddress.addressToP2pkhScript(toAddress);
        // Change goes back to the first selected UTXO's address.
        byte[] changeScript = PivxAddress.addressToP2pkhScript(inputKeys[0].address());

        byte[] txBytes = buildAndSign(sel.selected, inputKeys, changeScript, toScript, amount, sel.change);
        return result(txBytes, sel.selected, amount, sel.fee);
    }

    // ---- shared helpers ----

    private static void requireTransparentDest(String toAddress) {
        if (toAddress.startsWith("ps")) {
            throw new IllegalArgumentException(SHIELD_DEST_ERROR);
        }
    }

    private static void requireValidAmount(long amount) {
        if (amount <= 0) {
            throw new IllegalArgumentException("amount must be positive: " + amount);
        }
    }

    /**
     * Fold a change output below the dust threshold into the fee — nodes reject
     * sub-dust outputs as nonstandard, and reference wallets donate it to miners.
     */
    private static Selection foldDustChange(List<Utxo> selected, long fee, long change) {
        if (change > 0 && change < CoinSelector.MIN_CHANGE) {
            fee += change;
            change = 0;
        }
        return new Selection(selected, fee, change);
    }

    /** Coin selection outcome: chosen inputs + the fee/change they imply. */
    private record Selection(List<Utxo> selected, long fee, long change) {}

    /**
     * Coin selection: BnB (changeless, 1 output) first — avoids the change fee
     * and improves privacy — then Knapsack with a change output as fallback.
     */
    private static Selection selectWithFee(List<Utxo> utxos, long amount) {
        Optional<List<Utxo>> bnb = CoinSelector.selectBnB(utxos, amount, 1);
        if (bnb.isPresent()) {
            List<Utxo> selected = bnb.get();
            // Changeless: everything above the payment is fee (BnB may leave up
            // to MIN_CHANGE of surplus for the miners on top of the estimate).
            long total = selected.stream().mapToLong(Utxo::amount).sum();
            return new Selection(selected, total - amount, 0);
        }
        List<Utxo> selected = CoinSelector.selectKnapsack(utxos, amount, 2);
        long fee = CoinSelector.estimateFee(selected.size(), 2);
        long total = selected.stream().mapToLong(Utxo::amount).sum();
        long change = total - Math.addExact(amount, fee);
        if (change < 0) {
            throw new IllegalArgumentException(
                    "Insufficient public balance: need " + (amount + fee) + " sat");
        }
        return foldDustChange(selected, fee, change);
    }

    private static TransparentTransactionResult result(byte[] txBytes, List<Utxo> selected,
                                                       long amount, long fee) {
        List<SpentOutpoint> spent = new ArrayList<>(selected.size());
        for (Utxo u : selected) {
            spent.add(new SpentOutpoint(u.txid(), u.vout()));
        }
        return new TransparentTransactionResult(ByteUtil.toHex(txBytes), spent, amount, fee);
    }

    // ---- core tx assembly (single- and multi-index paths share this) ----

    /**
     * Assemble and sign the v1 tx. {@code inputKeys[i]} is the key that owns
     * (and signs) input {@code i}; {@code changeScript} receives any change.
     */
    private static byte[] buildAndSign(List<Utxo> selected,
                                       TransparentKeys.TransparentKey[] inputKeys,
                                       byte[] changeScript, byte[] toScript,
                                       long amount, long change) {
        // ECKey construction is comparatively expensive; share per unique key.
        Map<TransparentKeys.TransparentKey, ECKey> ecKeys = new HashMap<>();
        Map<TransparentKeys.TransparentKey, byte[]> scripts = new HashMap<>();

        ByteArrayOutputStream tx = new ByteArrayOutputStream();
        ByteUtil.writeLeU32(tx, 1); // version
        VarInt.write(tx, selected.size());

        for (int inputIdx = 0; inputIdx < selected.size(); inputIdx++) {
            Utxo utxo = selected.get(inputIdx);
            TransparentKeys.TransparentKey key = inputKeys[inputIdx];
            byte[] pubkey = key.pubkey();
            ECKey ecKey = ecKeys.computeIfAbsent(key, k -> ECKey.fromPrivate(k.privkey(), true));
            byte[] inputScript = scripts.computeIfAbsent(key,
                    k -> PivxAddress.addressToP2pkhScript(k.address()));

            byte[] txidBytes = ByteUtil.fromHex(utxo.txid());
            ByteUtil.reverseInPlace(txidBytes);
            tx.write(txidBytes, 0, 32);
            ByteUtil.writeLeU32(tx, utxo.vout());

            byte[] sighash = computeSighash(selected, inputScript, inputIdx,
                    amount, change, toScript, changeScript);
            // sign() already returns a canonicalised (Low-S) signature.
            ECKey.ECDSASignature sig = ecKey.sign(Sha256Hash.wrap(sighash));
            byte[] sigBytes = sig.encodeToDER();
            // Append SIGHASH_ALL flag byte.
            byte[] sigWithHashType = new byte[sigBytes.length + 1];
            System.arraycopy(sigBytes, 0, sigWithHashType, 0, sigBytes.length);
            sigWithHashType[sigBytes.length] = 0x01;

            int scriptSigLen = sigWithHashType.length + pubkey.length + 2;
            VarInt.write(tx, scriptSigLen);
            tx.write(sigWithHashType.length); // push sig (fits in 1 byte for typical 70-72 byte DER)
            tx.write(sigWithHashType, 0, sigWithHashType.length);
            tx.write(pubkey.length); // push pubkey
            tx.write(pubkey, 0, pubkey.length);

            ByteUtil.writeLeU32(tx, 0xffffffff); // sequence
        }

        writeOutputs(tx, amount, toScript, change, changeScript);
        ByteUtil.writeLeU32(tx, 0); // locktime
        return tx.toByteArray();
    }

    /**
     * Compute SIGHASH_ALL for a specific input in a v1 transparent tx.
     *
     * <p>Preimage: {@code version + varint(inputs) + [txid_reversed + vout +
     * (signing_script at signing_index | 0x00 elsewhere) + sequence]* + outputs +
     * locktime + SIGHASH_ALL}, then double-SHA256. The outputs section must be
     * byte-identical to the final tx (SIGHASH_ALL commits to all outputs), so
     * the change output always carries {@code changeScript} — not the signing
     * input's script.
     */
    static byte[] computeSighash(List<Utxo> inputs, byte[] signingScript, int signingIndex,
                                 long amount, long change, byte[] toScript, byte[] changeScript) {
        ByteArrayOutputStream preimage = new ByteArrayOutputStream();
        ByteUtil.writeLeU32(preimage, 1); // version
        VarInt.write(preimage, inputs.size());

        for (int i = 0; i < inputs.size(); i++) {
            Utxo utxo = inputs.get(i);
            byte[] txidBytes = ByteUtil.fromHex(utxo.txid());
            ByteUtil.reverseInPlace(txidBytes);
            preimage.write(txidBytes, 0, 32);
            ByteUtil.writeLeU32(preimage, utxo.vout());

            if (i == signingIndex) {
                VarInt.write(preimage, signingScript.length);
                preimage.write(signingScript, 0, signingScript.length);
            } else {
                preimage.write(0x00);
            }
            ByteUtil.writeLeU32(preimage, 0xffffffff);
        }

        writeOutputs(preimage, amount, toScript, change, changeScript);
        ByteUtil.writeLeU32(preimage, 0); // locktime
        ByteUtil.writeLeU32(preimage, 1); // SIGHASH_ALL
        return PivxAddress.doubleSha256(preimage.toByteArray());
    }

    /** Write the output section (payment + optional change), shared by tx body and sighash preimage. */
    private static void writeOutputs(ByteArrayOutputStream buf, long amount, byte[] toScript,
                                     long change, byte[] changeScript) {
        VarInt.write(buf, change > 0 ? 2 : 1);
        ByteUtil.writeLeU64(buf, amount);
        VarInt.write(buf, toScript.length);
        buf.write(toScript, 0, toScript.length);
        if (change > 0) {
            ByteUtil.writeLeU64(buf, change);
            VarInt.write(buf, changeScript.length);
            buf.write(changeScript, 0, changeScript.length);
        }
    }
}
