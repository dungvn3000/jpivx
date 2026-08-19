package dev.jpivx.wallet.shield;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Incremental parser for the PIVX node's binary shield stream
 * ({@code GET /getshielddata?startBlock=N}).
 *
 * <p>Wire format — a sequence of packets, each {@code [4-byte LE length][payload]}:
 * <pre>
 *   payload[0] == 0x5d → block marker, one of two formats:
 *     • footer (9 bytes = 0x5d + height + time) AFTER txs — PivxNodeController
 *       format, what PIVX Core's REST actually serves
 *     • header (5 bytes = 0x5d + height) BEFORE txs — compact bridge format
 *   payload[0] == 0x03 → full raw tx packet
 *   payload[0] == 0x04 → compact tx packet
 * </pre>
 *
 * <p>Grouping semantics: txs following a block marker attach to that OPEN
 * block; a footer commits the buffered txs under its height; a new header
 * commits the previously-open block first. Parser state (open block, buffered
 * txs) persists across {@link #nextBatch} calls, so a block is only ever
 * returned complete.
 *
 * <p><b>Deliberate divergence from the Rust kit:</b> {@code sync::parse_next_blocks}
 * attaches txs to the last <i>committed</i> block whenever the batch already
 * contains one — which mis-groups pure footer streams beyond the first block
 * (every later block's txs land on the first block of the batch, and its
 * footer then opens an empty phantom block). MyPIVXWallet's
 * {@code BinaryShieldSyncer} and real node streams require strict
 * footer/heading grouping, implemented here. Heights on notes and
 * {@code last_block} stay exact because of this.
 */
public final class ShieldStreamParser {

    /** Maximum packet size (no single shield tx exceeds 1 MiB) — kit limit. */
    public static final int MAX_PACKET_SIZE = 1_048_576;

    private static final int TAG_BLOCK = 0x5d;
    private static final int TAG_FULL_TX = 0x03;
    private static final int TAG_COMPACT_TX = 0x04;

    private final InputStream in;

    /** Txs buffered ahead of their footer (footer format), kept across batches. */
    private final List<byte[]> pendingTxs = new ArrayList<>();

    /** Block opened by a header marker, still collecting txs (header format). */
    private MutableBlock openBlock;

    public ShieldStreamParser(InputStream in) {
        this.in = in;
    }

    /** Mutable in-flight block; converted to {@link ShieldBlock} on return. */
    private static final class MutableBlock {
        final int height;
        final List<byte[]> txs = new ArrayList<>();

        MutableBlock(int height) {
            this.height = height;
        }
    }

    /**
     * Parse the next batch of up to {@code maxBlocks} <b>complete</b> blocks
     * from the stream.
     *
     * @return {@code null} on clean end-of-stream (no more complete blocks),
     *         else the batch (size &le; {@code maxBlocks})
     * @throws IOException on malformed/truncated packets
     */
    public List<ShieldBlock> nextBatch(int maxBlocks) throws IOException {
        List<MutableBlock> blocks = new ArrayList<>();
        boolean hitEof = false;

        while (blocks.size() < maxBlocks) {
            Long length = readU32Le();
            if (length == null) {
                hitEof = true;
                break;
            }
            if (length > MAX_PACKET_SIZE) {
                throw new IOException("Packet too large: " + length
                        + " bytes (max " + MAX_PACKET_SIZE + ")");
            }
            if (length == 0) {
                throw new IOException("Zero-length packet in shield binary stream");
            }

            int len = length.intValue(); // safe: < 1 MiB at this point
            byte[] payload = in.readNBytes(len);
            if (payload.length < len) {
                throw new IOException("shield stream truncated mid-packet: got "
                        + payload.length + " of " + len + " bytes");
            }

            int tag = payload[0] & 0xff;
            if (tag == TAG_BLOCK) {
                // The two marker formats differ in payload length: a footer is
                // 9 bytes (0x5d + height + time), a header is 5 (0x5d + height).
                // Grouping by parser state alone would misread an EMPTY block's
                // footer as a header and shift every later block's txs.
                if (len == 9) {
                    // Footer AFTER txs (PivxNodeController / PIVX Core REST).
                    if (openBlock != null) {
                        throw new IOException("Mixed shield block marker formats: "
                                + "9-byte footer while a header block is open");
                    }
                    MutableBlock block = new MutableBlock(leu32(payload, 1));
                    block.txs.addAll(pendingTxs);
                    blocks.add(block);
                    pendingTxs.clear();
                } else if (len == 5) {
                    // Header BEFORE txs (compact bridge format); closes any open block.
                    if (!pendingTxs.isEmpty()) {
                        throw new IOException("Mixed shield block marker formats: "
                                + "5-byte header while " + pendingTxs.size()
                                + " txs await a footer");
                    }
                    if (openBlock != null) {
                        blocks.add(openBlock);
                    }
                    openBlock = new MutableBlock(leu32(payload, 1));
                } else {
                    throw new IOException("Bad block marker payload length: " + len
                            + " bytes (expected 5 for header or 9 for footer)");
                }
            } else if (tag == TAG_FULL_TX || tag == TAG_COMPACT_TX) {
                if (openBlock != null) {
                    openBlock.txs.add(payload);
                } else {
                    pendingTxs.add(payload);
                }
            } else {
                throw new IOException(String.format(
                        "Unknown packet type 0x%02x in shield binary stream", tag));
            }
        }

        if (hitEof) {
            // Footer format: txs only count once their footer arrives. A stream
            // ending mid-block would silently drop them — bail loudly instead.
            if (!pendingTxs.isEmpty()) {
                throw new IOException("shield stream truncated: " + pendingTxs.size()
                        + " buffered txs without a block footer");
            }
            // Header format: flush the final open block with whatever it collected.
            if (openBlock != null) {
                blocks.add(openBlock);
                openBlock = null;
            }
        }

        if (blocks.isEmpty()) {
            return null;
        }
        List<ShieldBlock> out = new ArrayList<>(blocks.size());
        for (MutableBlock b : blocks) {
            out.add(new ShieldBlock(b.height, List.copyOf(b.txs)));
        }
        return out;
    }

    /**
     * Read a 4-byte little-endian length (unsigned). Returns {@code null} on
     * clean end-of-stream (exactly at a packet boundary); a partial 1–3 byte
     * read means the stream was cut mid-length and is an error.
     */
    private Long readU32Le() throws IOException {
        byte[] buf = in.readNBytes(4);
        if (buf.length == 0) {
            return null;
        }
        if (buf.length < 4) {
            throw new IOException("shield stream truncated mid-length: got "
                    + buf.length + " of 4 bytes");
        }
        return ((long) buf[0] & 0xff)
                | (((long) buf[1] & 0xff) << 8)
                | (((long) buf[2] & 0xff) << 16)
                | (((long) buf[3] & 0xff) << 24);
    }

    private static int leu32(byte[] b, int off) {
        return (b[off] & 0xff)
                | ((b[off + 1] & 0xff) << 8)
                | ((b[off + 2] & 0xff) << 16)
                | ((b[off + 3] & 0xff) << 24);
    }
}
