package dev.jpivx.wallet.shield;

import java.util.List;

/**
 * One block's worth of shield data — raw tx packets (0x03 full / 0x04 compact,
 * tag byte included), keyed to a block height.
 *
 * <p>Mirrors {@code sapling::sync::ShieldBlock} from the Rust kit; fed to the
 * JNI {@code handle_blocks} bridge as JSON with hex-encoded txs.
 */
public record ShieldBlock(int height, List<byte[]> txs) {}
