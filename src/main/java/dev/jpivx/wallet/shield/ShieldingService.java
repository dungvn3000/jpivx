package dev.jpivx.wallet.shield;

import com.grack.nanojson.JsonArray;
import com.grack.nanojson.JsonObject;
import com.grack.nanojson.JsonWriter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import dev.jpivx.wallet.core.Utxo;
import dev.jpivx.wallet.crypto.ShieldKeys;
import dev.jpivx.wallet.tx.SpentOutpoint;
import dev.jpivx.wallet.tx.TransparentTransactionResult;

/**
 * Shielding (transparent &rarr; shield) send facade — the mirror image of
 * {@link ShieldSendService}.
 *
 * <p>Spends transparent UTXOs and pays a {@code ps1...} shield address, via
 * the Rust kit's {@code transparent::builder::create_shielding_transaction}
 * over JNI. The tx is a v3 Sapling transaction carrying a real output bundle,
 * so the Groth16 proving parameters are mandatory (unlike the pure
 * transparent&rarr;transparent path in
 * {@link dev.jpivx.wallet.tx.RawTransparentBuilder}).
 *
 * <p>Typical flow:
 * <pre>
 *   TransparentTransactionResult r = ShieldingService.createTransaction(
 *           mnemonic, utxos, shieldDest, amountSat, tip, params);
 *   broadcast(r.txhex());
 *   // then drop r.spent() from your UTXO set
 * </pre>
 *
 * <p><b>Kit-inherited constraints</b> (all enforced or documented here):
 * <ul>
 *   <li>Every input is signed with the key at {@code m/44'/119'/0'/0/0}, so
 *       all UTXOs must sit on the wallet's default transparent address —
 *       UTXOs tagged with a different {@link Utxo#hdIndex()} are rejected
 *       (both here and again natively, so the lower-level
 *       {@link ShieldKeys#createShieldingTransaction} path is covered too).</li>
 *   <li>Change returns as a <em>transparent</em> output to that same address,
 *       not as a shield note.</li>
 *   <li>No memo: the kit hardcodes an empty memo on the shield output.</li>
 *   <li>UTXO selection is largest-first, and the fee is charged for the shape
 *       {@code (n transparent inputs, 0 transparent outputs, 0 sapling spends,
 *       2 sapling outputs)}. Selection and fee come straight from the kit's
 *       {@code select_shielding_utxos} over JNI — never re-implemented here —
 *       so {@link #selectionFee} always agrees with the builder.</li>
 * </ul>
 */
public final class ShieldingService {

    private ShieldingService() {
        throw new AssertionError("no instances");
    }

    // ---------------------------------------------------------------------
    // High-level send
    // ---------------------------------------------------------------------

    /**
     * Build and sign a shielding transaction from a plain UTXO list.
     *
     * <p>Signing keys derive from the mnemonic natively; the Sapling anchor
     * is the empty tree, which is all a shielding tx needs — it carries no
     * shield spends to anchor.
     *
     * @param mnemonic    BIP39 mnemonic phrase
     * @param utxos       the wallet's transparent UTXOs (all on HD index 0)
     * @param toAddress   {@code ps1...} shield destination
     * @param amountSat   amount the recipient receives, in satoshi
     * @param blockHeight chain tip (expiry context)
     * @param params      Sapling proving params (must be {@link SaplingParams#present() present})
     * @return the parsed result (txhex, spent outpoints, amount, fee)
     * @throws IOException              on JSON (de)serialization failure
     * @throws IllegalArgumentException on a transparent destination, an empty
     *                                  UTXO list, a non-positive UTXO amount,
     *                                  a non-zero {@code hdIndex}, or
     *                                  insufficient balance
     * @throws IllegalStateException    if the native shield library is unavailable
     */
    public static TransparentTransactionResult createTransaction(
            String mnemonic, List<Utxo> utxos, String toAddress, long amountSat,
            long blockHeight, SaplingParams params) throws IOException {
        requireShieldDest(toAddress);
        if (amountSat <= 0) {
            throw new IllegalArgumentException("amount must be positive: " + amountSat);
        }
        requireSpendableUtxos(utxos);
        // The kit's own selection — throws "Insufficient public balance"
        // BEFORE the expensive (~50 MB, first use) parameter load.
        quoteFee(utxosJson(utxos), amountSat);

        String walletJson = ShieldSendService.buildWalletJson(
                mnemonic, 0, new ShieldState(0, "", List.of()), utxos);
        String resultJson = ShieldKeys.createShieldingTransaction(
                walletJson, toAddress, amountSat, blockHeight,
                params.spendPath().toString(), params.outputPath().toString());
        return parseResult(ShieldJson.parseObject(resultJson));
    }

    // ---------------------------------------------------------------------
    // Fee / selection preview (kit selection over JNI — no params needed)
    // ---------------------------------------------------------------------

    /**
     * The exact fee {@link #createTransaction} will be charged for sending
     * {@code amountSat}: the kit selects UTXOs largest-first until
     * {@code total >= amount + fee}, and the fee grows with the input count.
     *
     * <p>Validates the UTXO set the same way {@link #createTransaction} does,
     * so a quote never disagrees with the build.
     *
     * @return the fee in satoshi (for the selection the builder will make)
     * @throws IllegalArgumentException on an empty/invalid UTXO set or when
     *         the UTXOs cannot cover {@code amountSat} plus the fee
     * @throws IllegalStateException if the native shield library is unavailable
     */
    public static long selectionFee(List<Utxo> utxos, long amountSat) throws IOException {
        requireSpendableUtxos(utxos);
        return quoteFee(utxosJson(utxos), amountSat);
    }

    /**
     * Solve {@code --subtract-fee} / send-max: the largest recipient amount
     * {@code a} the builder can actually send with {@code a + fee <= budgetSat}
     * — equal to {@code budgetSat - fee} whenever the budget is fully
     * consumable. Pass the wallet's whole transparent balance as
     * {@code budgetSat} to send max.
     *
     * <p>Same contract as
     * {@link ShieldSendService#resolveSubtractFeeAmount(List, long, String)},
     * over transparent inputs instead of notes (shared solver:
     * {@link SubtractFee}).
     *
     * @throws IllegalArgumentException if {@code budgetSat} exceeds the UTXOs'
     *         total value or cannot cover the smallest possible fee
     */
    public static long resolveSubtractFeeAmount(List<Utxo> utxos, long budgetSat)
            throws IOException {
        requireSpendableUtxos(utxos);
        String utxosJson = utxosJson(utxos);
        return SubtractFee.resolve(budgetSat, totalValue(utxos), "shielding",
                amountSat -> quoteFee(utxosJson, amountSat));
    }

    // ---------------------------------------------------------------------
    // Internals
    // ---------------------------------------------------------------------

    /** One kit selection round over JNI — returns the builder-charged fee. */
    private static long quoteFee(String utxosJson, long amountSat) throws IOException {
        String json = ShieldKeys.selectShieldingUtxos(utxosJson, amountSat);
        return ShieldJson.parseObject(json).getLong("fee", 0);
    }

    /** Kit-shaped {@code SerializedUTXO} JSON array for the JNI selection. */
    private static String utxosJson(List<Utxo> utxos) {
        JsonArray arr = new JsonArray();
        for (Utxo u : utxos) {
            arr.add(u.toJson());
        }
        return JsonWriter.string(arr);
    }

    /** Sum of UTXO values, with the kit's wording on overflow. */
    private static long totalValue(List<Utxo> utxos) {
        long total = 0;
        for (Utxo u : utxos) {
            try {
                total = Math.addExact(total, u.amount());
            } catch (ArithmeticException e) {
                throw new IllegalArgumentException(
                        "UTXO total overflow — explorer returned malformed amounts");
            }
        }
        return total;
    }

    private static void requireShieldDest(String toAddress) {
        if (!ShieldSendService.isShieldDestination(toAddress)) {
            throw new IllegalArgumentException(
                    "Shielding requires a ps1... shield destination, got " + toAddress
                            + " — use RawTransparentBuilder for D... destinations");
        }
    }

    /**
     * The kit signs every input with the key at {@code m/44'/119'/0'/0/0} and
     * assumes that address' script on each one, so a UTXO from another HD slot
     * would be signed invalidly. Reject rather than broadcast a bad signature.
     * (The native layer re-checks the {@code hd_index} tags, covering direct
     * {@link ShieldKeys#createShieldingTransaction} callers too.)
     */
    private static void requireSpendableUtxos(List<Utxo> utxos) {
        if (utxos.isEmpty()) {
            throw new IllegalArgumentException("No transparent UTXOs available");
        }
        for (Utxo u : utxos) {
            if (u.amount() <= 0) {
                throw new IllegalArgumentException(
                        "UTXO " + u.txid() + ":" + u.vout() + " has a non-positive amount ("
                                + u.amount() + " sat) — explorer returned malformed data");
            }
            if (u.hdIndex() != 0) {
                throw new IllegalArgumentException(
                        "Shielding spends only UTXOs on the default address m/44'/119'/0'/0/0, "
                                + "but " + u.txid() + ":" + u.vout() + " is tagged hd_index="
                                + u.hdIndex() + " — move it to index 0 with a transparent send first");
            }
        }
    }

    /** Parse the bridge's {@code TransparentTransactionResult} JSON. */
    private static TransparentTransactionResult parseResult(JsonObject o) {
        JsonArray spentArr = o.getArray("spent");
        List<SpentOutpoint> spent = new ArrayList<>();
        if (spentArr != null) {
            for (int i = 0; i < spentArr.size(); i++) {
                JsonObject e = spentArr.getObject(i);
                if (e != null) {
                    spent.add(new SpentOutpoint(e.getString("txid", ""), e.getInt("vout", 0)));
                }
            }
        }
        return new TransparentTransactionResult(
                o.getString("txhex", ""), List.copyOf(spent),
                o.getLong("amount", 0), o.getLong("fee", 0));
    }
}
