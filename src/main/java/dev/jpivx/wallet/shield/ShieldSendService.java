package dev.jpivx.wallet.shield;

import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import dev.jpivx.wallet.core.PivAmount;
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

    private static final ObjectMapper MAPPER = new ObjectMapper();

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
        return MAPPER.readValue(resultJson, ShieldTxResult.class);
    }

    /**
     * Serialize a wallet into the Rust kit's {@code WalletData} JSON shape —
     * the format {@link ShieldKeys#createShieldTransaction} expects.
     *
     * <p>Field-for-field identical to the kit's serde form: 32-byte seed array,
     * bech32 extfvk, heights, commitment tree, unspent notes, normalized
     * mnemonic, and (always empty here) transparent UTXO list.
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
        byte[] seed64 = BIP39Service.toSeed(BIP39Service.parse(mnemonic));
        // Kit's WalletData::seed is [u8; 32] — the first half of the BIP39 seed.
        byte[] seed32 = Arrays.copyOf(seed64, 32);

        ObjectNode wallet = MAPPER.createObjectNode();
        wallet.put("version", 1);
        ArrayNode seedArr = wallet.putArray("seed");
        for (byte b : seed32) {
            seedArr.add(b & 0xff);
        }
        wallet.put("extfvk", ShieldKeys.extfvk(seed64));
        wallet.put("birthday_height", birthdayHeight);
        wallet.put("last_block", state.getLastBlock());
        wallet.put("commitment_tree", state.getCommitmentTree());
        wallet.set("unspent_notes", MAPPER.valueToTree(state.getUnspentNotes()));
        wallet.put("mnemonic", BIP39Service.normalize(mnemonic));
        wallet.putArray("unspent_utxos");
        return MAPPER.writeValueAsString(wallet);
    }

    // ---------------------------------------------------------------------
    // Subtract-fee fixpoint
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
                MAPPER.writeValueAsString(notes), budgetSat, transparentOuts(toAddress));
    }

    /**
     * Fixpoint for {@code --subtract-fee}: given a total {@code budgetSat},
     * find the recipient amount such that {@code recipient + fee == budgetSat},
     * where the fee is the builder's EXACT fee for the notes it will select.
     *
     * <p>The fee depends on how many notes the selection pulls in, and the
     * selection depends on the amount — so we iterate {@code selectShieldNotes}
     * until the fee stops changing. The sequence is monotone and bounded
     * (fee values live in a finite set of per-input-count fees), so a few
     * iterations always converge.
     *
     * @param notesJson  JSON array of the kit's {@code SerializedNote} shape
     * @param budgetSat  total sats the wallet may lose (recipient + fee)
     * @param tOut       transparent outputs (see {@link #transparentOuts})
     * @return the amount to pass to the builder (what the recipient receives)
     * @throws IllegalArgumentException if {@code budgetSat} cannot cover the
     *         smallest possible shield fee
     */
    public static long resolveSubtractFeeAmount(String notesJson, long budgetSat, long tOut)
            throws IOException {
        // Minimal one-spend fee: a 0-sat target selects exactly one note.
        long fee = selectShieldFee(notesJson, 0, tOut);
        for (int i = 0; i < 64; i++) {
            long sendAmount = budgetSat - fee;
            if (sendAmount <= 0) {
                throw new IllegalArgumentException("Amount " + PivAmount.formatSatToPiv(budgetSat)
                        + " is too small to cover the shield fee "
                        + PivAmount.formatSatToPiv(fee) + ".");
            }
            long newFee = selectShieldFee(notesJson, sendAmount, tOut);
            if (newFee == fee) {
                return sendAmount;
            }
            fee = newFee;
        }
        throw new IllegalStateException("shield fee selection did not converge after 64 rounds");
    }

    /** One JNI selection round — returns the builder-charged fee. */
    private static long selectShieldFee(String notesJson, long amountSat, long tOut)
            throws IOException {
        String json = ShieldKeys.selectShieldNotes(notesJson, amountSat, tOut, SAPLING_OUTS);
        return MAPPER.readValue(json, ShieldSelection.class).fee();
    }
}
