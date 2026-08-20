package dev.jpivx.wallet.shield;

import com.grack.nanojson.JsonArray;
import com.grack.nanojson.JsonObject;
import com.grack.nanojson.JsonWriter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import dev.jpivx.wallet.core.PivAmount;
import dev.jpivx.wallet.core.Utxo;
import dev.jpivx.wallet.crypto.BIP39Service;
import dev.jpivx.wallet.crypto.ShieldKeys;

/**
 * Shield send facade layered on the JNI primitives.
 *
 * <p>Typical flow — no manual JSON assembly required:
 * <pre>
 *   ShieldTxResult r = ShieldSendService.createTransaction(
 *           mnemonic, birthdayHeight, state, dest, amountSat, memo, tip, params);
 *   broadcast(r.txhex());
 *   state.removeSpentNotes(r.nullifiers()); // then persist state
 * </pre>
 */
public final class ShieldSendService {

    private ShieldSendService() {
        throw new AssertionError("no instances");
    }

    /** Sapling outputs per send (destination + change) — kit constant. */
    static final long SAPLING_OUTS = 2;

    /** True for a shield ({@code ps1...}) destination — mirrors the kit's HRP check. */
    public static boolean isShieldDestination(String toAddress) {
        return toAddress.startsWith("ps");
    }

    /** Transparent outputs for the tx shape (1 when deshielding to {@code D...}). */
    public static long transparentOuts(String toAddress) {
        return isShieldDestination(toAddress) ? 0 : 1;
    }

    // ---------------------------------------------------------------------
    // High-level send
    // ---------------------------------------------------------------------

    /**
     * Build and sign a shield transaction from the wallet's current state —
     * the one-call path for shield→shield and shield→transparent sends.
     *
     * <p>Assembles the kit's {@code WalletData} JSON from the mnemonic and
     * {@link ShieldState}, runs the JNI Groth16 builder, and parses the result.
     * After broadcasting, call {@link ShieldState#removeSpentNotes} with
     * {@link ShieldTxResult#nullifiers()} and persist the state.
     *
     * @param mnemonic       BIP39 mnemonic phrase
     * @param birthdayHeight wallet birthday block height
     * @param state          synced shield state (notes + commitment tree)
     * @param toAddress      {@code ps1...} (shield) or {@code D...} (deshield)
     * @param amountSat      amount the recipient receives, in satoshi
     * @param memo           memo text ({@code ""} for none; shield destinations only)
     * @param blockHeight    chain tip + 1 (expiry / anchor context)
     * @param params         Sapling proving params (must be {@link SaplingParams#present() present})
     * @return the parsed transaction result (txhex, nullifiers, amount, fee)
     * @throws IOException              on JSON (de)serialization failure
     * @throws IllegalArgumentException from the kit (insufficient balance, bad address, ...)
     * @throws IllegalStateException    if the native shield library is unavailable
     */
    public static ShieldTxResult createTransaction(String mnemonic, int birthdayHeight,
                                                   ShieldState state, String toAddress,
                                                   long amountSat, String memo, long blockHeight,
                                                   SaplingParams params) throws IOException {
        String walletJson = buildWalletJson(mnemonic, birthdayHeight, state);
        String resultJson = ShieldKeys.createShieldTransaction(
                walletJson, toAddress, amountSat, memo, blockHeight,
                params.spendPath().toString(), params.outputPath().toString());
        return ShieldTxResult.fromJson(ShieldJson.parseObject(resultJson));
    }

    /**
     * Serialize a wallet into the Rust kit's {@code WalletData} JSON shape —
     * the format {@link ShieldKeys#createShieldTransaction} expects.
     *
     * <p>Field-for-field identical to the kit's serde form: 32-byte seed array,
     * bech32 extfvk, heights, commitment tree, unspent notes, normalized
     * mnemonic, and an (empty) transparent UTXO list — shield sends spend
     * notes only. Use {@link #buildWalletJson(String, int, ShieldState, List)}
     * to hand the builder transparent UTXOs for a shielding (t&rarr;z) send.
     *
     * @param mnemonic       BIP39 mnemonic phrase
     * @param birthdayHeight wallet birthday block height
     * @param state          shield state carrying tree + notes + last block
     * @return the wallet JSON string
     * @throws IOException           on serialization failure
     * @throws IllegalStateException if the native shield library is unavailable
     */
    public static String buildWalletJson(String mnemonic, int birthdayHeight, ShieldState state)
            throws IOException {
        return buildWalletJson(mnemonic, birthdayHeight, state, List.of());
    }

    /**
     * Same as {@link #buildWalletJson(String, int, ShieldState)} but also
     * carries the wallet's transparent UTXOs — the form
     * {@link dev.jpivx.wallet.crypto.ShieldKeys#createShieldingTransaction}
     * needs, since a shielding tx spends from {@code unspent_utxos}.
     *
     * @param utxos transparent UTXOs to expose to the builder (may be empty)
     */
    public static String buildWalletJson(String mnemonic, int birthdayHeight, ShieldState state,
                                         List<Utxo> utxos) throws IOException {
        byte[] seed64 = BIP39Service.toSeed(BIP39Service.parse(mnemonic));
        // Kit's WalletData::seed is [u8; 32] — the first half of the BIP39 seed.
        byte[] seed32 = Arrays.copyOf(seed64, 32);

        JsonObject wallet = new JsonObject();
        wallet.put("version", 1);
        JsonArray seedArr = new JsonArray();
        for (byte b : seed32) {
            seedArr.add(b & 0xff);
        }
        wallet.put("seed", seedArr);
        wallet.put("extfvk", ShieldKeys.extfvk(seed64));
        wallet.put("birthday_height", birthdayHeight);
        wallet.put("last_block", state.getLastBlock());
        wallet.put("commitment_tree", state.getCommitmentTree());
        wallet.put("unspent_notes", SerializedNote.toJsonArray(state.getUnspentNotes()));
        wallet.put("mnemonic", BIP39Service.normalize(mnemonic));
        JsonArray utxoArr = new JsonArray();
        for (Utxo u : utxos) {
            utxoArr.add(u.toJson());
        }
        wallet.put("unspent_utxos", utxoArr);
        return JsonWriter.string(wallet);
    }

    // ---------------------------------------------------------------------
    // Subtract-fee / send-max
    // ---------------------------------------------------------------------

    /**
     * Typed variant of {@link #resolveSubtractFeeAmount(String, long, long)}:
     * takes the wallet's notes and the destination address directly.
     *
     * @param notes     the wallet's unspent notes (e.g. {@link ShieldState#getUnspentNotes()})
     * @param budgetSat total sats the wallet may lose (recipient + fee)
     * @param toAddress destination — decides the transparent-output count
     * @return the amount to pass to the builder (what the recipient receives)
     */
    public static long resolveSubtractFeeAmount(List<SerializedNote> notes, long budgetSat,
                                                String toAddress) throws IOException {
        return resolveSubtractFeeAmount(
                JsonWriter.string(SerializedNote.toJsonArray(notes)), budgetSat,
                transparentOuts(toAddress));
    }

    /**
     * Solve {@code --subtract-fee} / send-max: the largest recipient amount
     * {@code a} the builder can actually send with {@code a + fee <= budgetSat},
     * where the fee is the builder's EXACT fee for the notes it will select
     * for {@code a}. Equals {@code budgetSat - fee} whenever the budget is
     * fully consumable; solved by {@link SubtractFee} (binary search — the
     * fee is a step function of the amount, so a naive fixpoint can
     * oscillate).
     *
     * @param notesJson  JSON array of the kit's {@code SerializedNote} shape
     * @param budgetSat  total sats the wallet may lose (recipient + fee)
     * @param tOut       transparent outputs (see {@link #transparentOuts})
     * @return the amount to pass to the builder (what the recipient receives)
     * @throws IllegalArgumentException if {@code budgetSat} exceeds the notes'
     *         total value or cannot cover the smallest possible shield fee
     */
    public static long resolveSubtractFeeAmount(String notesJson, long budgetSat, long tOut)
            throws IOException {
        return SubtractFee.resolve(budgetSat, totalNoteValue(notesJson), "shield",
                amountSat -> selectShieldFee(notesJson, amountSat, tOut));
    }

    /** Sum of {@code note.value} across a kit-shaped notes JSON array. */
    private static long totalNoteValue(String notesJson) throws IOException {
        JsonArray notes;
        try {
            notes = com.grack.nanojson.JsonParser.array().from(notesJson);
        } catch (com.grack.nanojson.JsonParserException e) {
            throw new IOException("malformed notes JSON: " + e.getMessage(), e);
        }
        long total = 0;
        for (int i = 0; i < notes.size(); i++) {
            JsonObject note = notes.getObject(i) == null
                    ? null : notes.getObject(i).getObject("note");
            long value = note == null ? 0 : note.getLong("value", 0);
            try {
                total = Math.addExact(total, value);
            } catch (ArithmeticException e) {
                throw new IllegalArgumentException(
                        "note total overflow — malformed note values");
            }
        }
        return total;
    }

    /** One JNI selection round — returns the builder-charged fee. */
    private static long selectShieldFee(String notesJson, long amountSat, long tOut)
            throws IOException {
        String json = ShieldKeys.selectShieldNotes(notesJson, amountSat, tOut, SAPLING_OUTS);
        return ShieldSelection.fromJson(ShieldJson.parseObject(json)).fee();
    }
}
