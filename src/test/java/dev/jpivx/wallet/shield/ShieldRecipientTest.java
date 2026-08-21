package dev.jpivx.wallet.shield;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Validation and wire shape of the multi-recipient shield send inputs. */
class ShieldRecipientTest {

    private static final String SHIELD = "ps124f3dxhmtygh72cu8f05t94yey59at3armnk44uctjwdqf9uk2grnth3h5uszmqzzeev7kcr7rn";
    private static final String TRANSPARENT = "DPo9TNvPwy2ZfmVM3CRCxbBvh6NojguWXJ";

    @Test
    void validatesAddressAmountAndMemo() {
        assertThrows(IllegalArgumentException.class, () -> new ShieldRecipient("", 1_000L));
        assertThrows(IllegalArgumentException.class, () -> new ShieldRecipient(SHIELD, 0L));
        assertThrows(IllegalArgumentException.class, () -> new ShieldRecipient(SHIELD, -5L));
        assertThrows(IllegalArgumentException.class, () -> new ShieldRecipient(SHIELD, 1_000L, null));
        // The dust rule is a transparent-output standardness rule only.
        assertThrows(IllegalArgumentException.class, () -> new ShieldRecipient(TRANSPARENT, 545L));
        assertEquals(100L, new ShieldRecipient(SHIELD, 100L).amountSat(),
                "shield outputs have no dust threshold");
    }

    @Test
    void serializesTheKitsWireShape() {
        List<ShieldRecipient> recipients = List.of(
                new ShieldRecipient(SHIELD, 2_000_000L, "hi"),
                new ShieldRecipient(TRANSPARENT, 1_000_000L));
        String json = com.grack.nanojson.JsonWriter.string(
                ShieldRecipient.toJsonArray(recipients));
        assertEquals("[{\"address\":\"" + SHIELD + "\",\"amount\":2000000,\"memo\":\"hi\"},"
                + "{\"address\":\"" + TRANSPARENT + "\",\"amount\":1000000,\"memo\":\"\"}]", json);
    }

    @Test
    void feeShapeCountsRealOutputsFlooredAtTwoSapling() {
        List<ShieldRecipient> twoShield = List.of(
                new ShieldRecipient(SHIELD, 1L), new ShieldRecipient(SHIELD, 1L));
        assertEquals(0, ShieldSendService.transparentOuts(twoShield));
        assertEquals(3, ShieldSendService.saplingOuts(twoShield), "2 recipients + change");

        List<ShieldRecipient> mixed = List.of(
                new ShieldRecipient(SHIELD, 1L), new ShieldRecipient(TRANSPARENT, 546L));
        assertEquals(1, ShieldSendService.transparentOuts(mixed));
        assertEquals(2, ShieldSendService.saplingOuts(mixed),
                "1 shield recipient + change, floored at the sapling pad of 2");

        List<ShieldRecipient> deshieldOnly = List.of(new ShieldRecipient(TRANSPARENT, 546L));
        assertEquals(1, ShieldSendService.transparentOuts(deshieldOnly));
        assertEquals(2, ShieldSendService.saplingOuts(deshieldOnly),
                "change only, still padded to 2 — matches the historical (1, 2) shape");
    }
}
