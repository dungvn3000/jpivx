package dev.jpivx.wallet.shield;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Mutable shield sync state used by {@link ShieldSyncService}.
 *
 * <p>Holds the three fields that change during a shield sync round:
 * the Sapling commitment tree, the set of unspent notes, and the last
 * synced block height. Callers are expected to persist this state between
 * sessions (e.g. serialize to JSON and store alongside the BIP39 seed).
 *
 * <p>This class intentionally has no dependency on any wallet storage layer,
 * making it usable as a standalone library primitive.
 */
public final class ShieldState {

    private int lastBlock;
    private String commitmentTree;
    private List<SerializedNote> unspentNotes;

    /**
     * Create a new shield state.
     *
     * @param lastBlock      last synced block height (use birthday height on first sync)
     * @param commitmentTree hex-encoded Sapling commitment tree (empty string on first sync)
     * @param unspentNotes   currently known unspent Sapling notes (empty list on first sync)
     */
    public ShieldState(int lastBlock, String commitmentTree, List<SerializedNote> unspentNotes) {
        this.lastBlock = lastBlock;
        this.commitmentTree = commitmentTree != null ? commitmentTree : "";
        this.unspentNotes = unspentNotes != null ? new ArrayList<>(unspentNotes) : new ArrayList<>();
    }

    /** Last successfully synced block height. */
    public int getLastBlock() { return lastBlock; }
    public void setLastBlock(int lastBlock) { this.lastBlock = lastBlock; }

    /** Hex-encoded Sapling commitment tree after the last sync. */
    public String getCommitmentTree() { return commitmentTree; }
    public void setCommitmentTree(String commitmentTree) { this.commitmentTree = commitmentTree; }

    /** Unspent Sapling notes after the last sync (read-only view). */
    public List<SerializedNote> getUnspentNotes() {
        return Collections.unmodifiableList(unspentNotes);
    }
    public void setUnspentNotes(List<SerializedNote> unspentNotes) {
        this.unspentNotes = unspentNotes != null ? new ArrayList<>(unspentNotes) : new ArrayList<>();
    }

    /**
     * Sum of all note values in satoshis, using the {@code value} field inside
     * each note's opaque JSON blob (matches the Rust kit's serialization shape).
     */
    public long getShieldBalance() {
        long sum = 0;
        for (SerializedNote n : unspentNotes) {
            if (n.note() != null) {
                sum += n.note().getLong("value", 0);
            }
        }
        return sum;
    }

    /**
     * Remove notes whose nullifier appears in {@code nullifiers} — call after
     * broadcasting a shield tx (with {@link ShieldTxResult#nullifiers()}) so
     * the local state reflects the spend before the next sync sees it.
     *
     * @param nullifiers hex-encoded nullifiers of spent notes
     * @return number of notes removed
     */
    public int removeSpentNotes(Collection<String> nullifiers) {
        if (nullifiers == null || nullifiers.isEmpty()) {
            return 0;
        }
        Set<String> spent = new HashSet<>(nullifiers);
        int before = unspentNotes.size();
        unspentNotes.removeIf(n -> spent.contains(n.nullifier()));
        return before - unspentNotes.size();
    }

    @Override
    public String toString() {
        return "ShieldState{lastBlock=" + lastBlock
                + ", notes=" + unspentNotes.size() + "}";
    }
}
