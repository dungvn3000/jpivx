package dev.jpivx.wallet.shield;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link ShieldStreamParser} with synthetic streams covering
 * both wire formats (footer and header block markers) and every error path of
 * the Rust kit's {@code sync::parse_next_blocks}.
 */
class ShieldStreamParserTest {

    private static byte[] packet(byte... payload) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int len = payload.length;
        out.write(len & 0xff);
        out.write((len >>> 8) & 0xff);
        out.write((len >>> 16) & 0xff);
        out.write((len >>> 24) & 0xff);
        out.writeBytes(payload);
        return out.toByteArray();
    }

    private static byte[] txPacket(int tag, int idByte) {
        // tag + a couple of dummy content bytes
        return packet((byte) tag, (byte) idByte, (byte) (idByte + 1));
    }

    private static byte[] blockMarker(int height, boolean withTime) {
        ByteArrayOutputStream p = new ByteArrayOutputStream();
        p.write(0x5d);
        p.write(height & 0xff);
        p.write((height >>> 8) & 0xff);
        p.write((height >>> 16) & 0xff);
        p.write((height >>> 24) & 0xff);
        if (withTime) {
            p.writeBytes(new byte[]{0, 0, 0, 0});
        }
        return packet(p.toByteArray());
    }

    private static ByteArrayInputStream stream(byte[]... chunks) {
        ByteArrayOutputStream all = new ByteArrayOutputStream();
        for (byte[] c : chunks) {
            all.writeBytes(c);
        }
        return new ByteArrayInputStream(all.toByteArray());
    }

    // ---- footer format (PIVX Core REST: txs first, 9-byte 0x5d footer last) ----

    @Test
    void footerFormatGroupsTxsIntoBlocks() throws IOException {
        ByteArrayInputStream in = stream(
                txPacket(0x03, 1), txPacket(0x03, 3), blockMarker(100, true),
                txPacket(0x03, 9), blockMarker(101, true));
        ShieldStreamParser parser = new ShieldStreamParser(in);

        List<ShieldBlock> batch = parser.nextBatch(10);
        assertEquals(2, batch.size());

        assertEquals(100, batch.get(0).height());
        assertEquals(2, batch.get(0).txs().size());
        assertArrayEquals(new byte[]{0x03, 1, 2}, batch.get(0).txs().get(0));
        assertArrayEquals(new byte[]{0x03, 3, 4}, batch.get(0).txs().get(1));

        assertEquals(101, batch.get(1).height());
        assertEquals(1, batch.get(1).txs().size());

        assertNull(parser.nextBatch(10));
    }

    @Test
    void footerFormatHonoursBatchLimit() throws IOException {
        ByteArrayInputStream in = stream(
                txPacket(0x03, 1), blockMarker(100, true),
                txPacket(0x03, 9), blockMarker(101, true));
        ShieldStreamParser parser = new ShieldStreamParser(in);

        List<ShieldBlock> first = parser.nextBatch(1);
        assertEquals(1, first.size());
        assertEquals(100, first.get(0).height());

        List<ShieldBlock> second = parser.nextBatch(1);
        assertEquals(1, second.size());
        assertEquals(101, second.get(0).height());

        assertNull(parser.nextBatch(1));
    }

    // ---- header format (compact bridge: 5-byte 0x5d header before txs) ----

    @Test
    void headerFormatAttachesTxsToOpenBlock() throws IOException {
        ByteArrayInputStream in = stream(
                blockMarker(200, false), txPacket(0x04, 1), txPacket(0x04, 2),
                blockMarker(201, false), txPacket(0x04, 3));
        ShieldStreamParser parser = new ShieldStreamParser(in);

        List<ShieldBlock> batch = parser.nextBatch(10);
        assertEquals(2, batch.size());
        assertEquals(200, batch.get(0).height());
        assertEquals(2, batch.get(0).txs().size());
        assertEquals(201, batch.get(1).height());
        assertEquals(1, batch.get(1).txs().size());
        // compact tag byte is kept in the payload
        assertEquals(0x04, batch.get(1).txs().get(0)[0]);
    }

    @Test
    void consecutiveHeadersYieldEmptyBlocks() throws IOException {
        ByteArrayInputStream in = stream(
                blockMarker(300, false), blockMarker(301, false), txPacket(0x04, 7));
        ShieldStreamParser parser = new ShieldStreamParser(in);

        List<ShieldBlock> batch = parser.nextBatch(10);
        assertEquals(2, batch.size());
        assertTrue(batch.get(0).txs().isEmpty());
        assertEquals(1, batch.get(1).txs().size());
    }

    // ---- error paths ----

    @Test
    void emptyStreamYieldsNull() throws IOException {
        ShieldStreamParser parser = new ShieldStreamParser(new ByteArrayInputStream(new byte[0]));
        assertNull(parser.nextBatch(10));
    }

    @Test
    void partialLengthIsCleanEof() throws IOException {
        ShieldStreamParser parser =
                new ShieldStreamParser(new ByteArrayInputStream(new byte[]{0x10, 0x00}));
        assertNull(parser.nextBatch(10));
    }

    @Test
    void truncatedPayloadErrors() {
        // Length says 10 bytes but only 3 arrive.
        ByteArrayInputStream in = new ByteArrayInputStream(
                new byte[]{10, 0, 0, 0, 0x03, 0x01, 0x02});
        assertThrows(IOException.class, () -> new ShieldStreamParser(in).nextBatch(10));
    }

    @Test
    void bufferedTxsWithoutFooterError() {
        // Footer format stream that never closes its block.
        ByteArrayInputStream in = stream(txPacket(0x03, 1));
        assertThrows(IOException.class, () -> new ShieldStreamParser(in).nextBatch(10));
    }

    @Test
    void zeroLengthPacketErrors() {
        ByteArrayInputStream in = new ByteArrayInputStream(new byte[]{0, 0, 0, 0});
        assertThrows(IOException.class, () -> new ShieldStreamParser(in).nextBatch(10));
    }

    @Test
    void oversizedPacketErrors() {
        int big = ShieldStreamParser.MAX_PACKET_SIZE + 1;
        ByteArrayInputStream in = new ByteArrayInputStream(new byte[]{
                (byte) (big & 0xff), (byte) ((big >>> 8) & 0xff),
                (byte) ((big >>> 16) & 0xff), (byte) ((big >>> 24) & 0xff)});
        assertThrows(IOException.class, () -> new ShieldStreamParser(in).nextBatch(10));
    }

    @Test
    void unknownTagErrors() {
        ByteArrayInputStream in = stream(packet((byte) 0x7f, (byte) 1));
        assertThrows(IOException.class, () -> new ShieldStreamParser(in).nextBatch(10));
    }
}
