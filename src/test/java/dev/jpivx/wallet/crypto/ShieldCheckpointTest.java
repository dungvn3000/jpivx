package dev.jpivx.wallet.crypto;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The embedded mainnet checkpoint table, read back over JNI.
 *
 * <p>Golden values come from the kit's {@code checkpoints::MAINNET_CHECKPOINTS}
 * (first and last entries). A wallet that seeds its commitment tree from
 * anything other than one of these produces an anchor no node ever had, and its
 * spends are rejected with {@code bad-txns-shielded-requirements-not-met} — so
 * the lookup being exact matters more than it looks.
 */
class ShieldCheckpointTest {

    /** First entry: the empty tree, valid only before Sapling activation. */
    private static final int FIRST_HEIGHT = 2_700_000;
    private static final String FIRST_TREE = "000000";

    /** Latest entry at the time of writing; new checkpoints append after it. */
    private static final int LATEST_HEIGHT = 5_236_346;
    private static final String LATEST_TREE_PREFIX =
            "0167b593e469d49bae4dd999dbbb5bebb556b22fa0cc255660046859c859ace306";

    static boolean shieldAvailable() {
        return ShieldKeys.isAvailable();
    }

    @Test
    @EnabledIf("shieldAvailable")
    void exactHeightReturnsThatCheckpoint() {
        ShieldKeys.Checkpoint first = ShieldKeys.checkpoint(FIRST_HEIGHT);
        assertEquals(FIRST_HEIGHT, first.height());
        assertEquals(FIRST_TREE, first.commitmentTree());
    }

    @Test
    @EnabledIf("shieldAvailable")
    void heightsBetweenCheckpointsSnapDownward() {
        ShieldKeys.Checkpoint between = ShieldKeys.checkpoint(FIRST_HEIGHT + 1);
        assertEquals(FIRST_HEIGHT, between.height(), "must never snap forward");
        assertEquals(FIRST_TREE, between.commitmentTree());
    }

    @Test
    @EnabledIf("shieldAvailable")
    void heightsAboveTheTableClampToTheLatestCheckpoint() {
        ShieldKeys.Checkpoint tip = ShieldKeys.checkpoint(Integer.MAX_VALUE);
        assertTrue(tip.height() >= LATEST_HEIGHT,
                "expected at least the known latest checkpoint, got " + tip.height());
        if (tip.height() == LATEST_HEIGHT) {
            assertTrue(tip.commitmentTree().startsWith(LATEST_TREE_PREFIX));
        }
        assertTrue(tip.commitmentTree().length() > FIRST_TREE.length(),
                "a mid-chain checkpoint carries a real tree, not the empty one");
    }

    @Test
    @EnabledIf("shieldAvailable")
    void heightsBelowTheTableClampToTheFirstCheckpoint() {
        ShieldKeys.Checkpoint zero = ShieldKeys.checkpoint(0);
        assertEquals(FIRST_HEIGHT, zero.height());
        assertEquals(FIRST_TREE, zero.commitmentTree());
    }
}
