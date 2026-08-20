package dev.jpivx.wallet.shield;

import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

import dev.jpivx.wallet.crypto.ShieldKeys;
import dev.jpivx.wallet.network.ShieldNodeClient;

/**
 * Shield sync orchestration, mirroring the kit's WASM consumer
 * ({@code wasm.rs::handle_blocks} caller).
 *
 * <p>Flow: stream {@code /getshielddata} from {@code state.lastBlock + 1},
 * parse the binary stream into batches, push each batch through the JNI
 * {@code handle_blocks} bridge, then merge back — exactly like the kit:
 * <pre>
 *   unspent_notes = result.updated_notes
 *   unspent_notes += result.new_notes
 *   unspent_notes.removeIf(nullifier ∈ result.nullifiers)
 *   commitment_tree = result.commitment_tree
 *   last_block = max batch height
 * </pre>
 *
 * <p>The {@code afterBatch} callback fires after every applied batch so the
 * caller can persist the state — progress survives interruption.
 */
public final class ShieldSyncService {

    /** Default blocks per JNI batch (matches MyPIVXWallet's 200). */
    public static final int DEFAULT_BATCH_BLOCKS = 200;

    /** Shared ObjectMapper for JNI JSON wire format. */
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private ShieldSyncService() {
        throw new AssertionError("no instances");
    }

    /**
     * Sync the shield state from the node's shield stream.
     *
     * @param bip39Seed  64-byte BIP39 seed (used to derive the Sapling viewing key)
     * @param state      mutable shield state; updated in place (caller persists)
     * @param client     shield node REST client
     * @param batchSize  blocks per JNI batch (typically {@link #DEFAULT_BATCH_BLOCKS})
     * @param afterBatch callback after each applied batch — e.g. {@code s -> save(s)};
     *                   may be {@code null}
     * @param progress   receives {@code (lastBatchHeight, tip)} after each batch;
     *                   may be {@code null}
     * @return number of blocks processed (0 if already at tip)
     */
    public static int syncShield(byte[] bip39Seed, ShieldState state, ShieldNodeClient client,
                                 int batchSize, Consumer<ShieldState> afterBatch,
                                 ProgressListener progress) throws Exception {
        if (!ShieldKeys.isAvailable()) {
            throw new IllegalStateException(
                    "Shield sync requires the native library: " + ShieldKeys.unavailableReason());
        }

        int tip = client.getBlockCount();
        int start = state.getLastBlock() + 1;
        if (start > tip) {
            return 0;
        }

        // The viewing key is derivable from the seed at any time; no reliance
        // on any persisted extfvk field.
        String extfvk = ShieldKeys.extfvk(bip39Seed);

        int processed = 0;
        try (InputStream stream = client.getShieldData(start)) {
            ShieldStreamParser parser = new ShieldStreamParser(stream);
            List<ShieldBlock> batch;
            while ((batch = parser.nextBatch(batchSize)) != null) {
                applyBatch(state, extfvk, batch);
                processed += batch.size();
                if (afterBatch != null) {
                    afterBatch.accept(state);
                }
                if (progress != null) {
                    progress.onProgress(state.getLastBlock(), tip);
                }
            }
        }

        // The stream contains only blocks with shield activity; the state is
        // now caught up to the chain tip regardless of the last shield block.
        // Truncation mid-length/mid-packet or txs missing their footer throw in
        // the parser above; a cut exactly at a packet boundary is not detectable
        // (the protocol has no end marker), nor is a load balancer serving
        // getblockcount and getshielddata from different nodes.
        state.setLastBlock(tip);
        if (afterBatch != null) {
            afterBatch.accept(state);
        }
        return processed;
    }

    /** Run one batch through JNI and merge the result back into the state. */
    static void applyBatch(ShieldState state, String extfvk, List<ShieldBlock> batch)
            throws Exception {
        String notesJson = MAPPER.writeValueAsString(state.getUnspentNotes());
        String blocksJson = toBlocksJson(batch);

        String resultJson = ShieldKeys.handleBlocks(
                state.getCommitmentTree(), blocksJson, extfvk, notesJson);
        HandleBlocksResult result = MAPPER.readValue(resultJson, HandleBlocksResult.class);

        state.setCommitmentTree(result.commitmentTree());

        List<SerializedNote> merged = new ArrayList<>(result.updatedNotes());
        merged.addAll(result.newNotes());
        if (!result.nullifiers().isEmpty()) {
            Set<String> spent = new HashSet<>(result.nullifiers());
            merged.removeIf(n -> spent.contains(n.nullifier()));
        }
        state.setUnspentNotes(merged);

        int maxHeight = batch.stream().mapToInt(ShieldBlock::height).max().orElseThrow();
        state.setLastBlock(maxHeight);
    }

    /** Serialize blocks into the JNI wire shape: hex txs per the bridge's contract. */
    static String toBlocksJson(List<ShieldBlock> blocks) {
        HexFormat hex = HexFormat.of();
        ArrayNode out = MAPPER.createArrayNode();
        for (ShieldBlock b : blocks) {
            ObjectNode o = out.addObject();
            o.put("height", b.height());
            ArrayNode txs = o.putArray("txs");
            for (byte[] tx : b.txs()) {
                txs.add(hex.formatHex(tx));
            }
        }
        return out.toString();
    }

    /** Progress callback: last synced height + chain tip. */
    @FunctionalInterface
    public interface ProgressListener {
        void onProgress(int lastSyncedHeight, int tip);
    }
}
