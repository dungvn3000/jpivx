package dev.jpivx.wallet.crypto;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Full address validation through the kit's {@code decode_generic_address}
 * over JNI — including the shield checks a pure-Java validator cannot do
 * (bech32 checksum + jubjub point decompression).
 */
class AddressValidationJniTest {

    /** Golden shield address for the shared test mnemonic (kit cross-verified). */
    private static final String SHIELD =
            "ps124f3dxhmtygh72cu8f05t94yey59at3armnk44uctjwdqf9uk2grnth3h5uszmqzzeev7kcr7rn";
    /** Golden transparent address for the shared test mnemonic. */
    private static final String TRANSPARENT = "DPo9TNvPwy2ZfmVM3CRCxbBvh6NojguWXJ";

    static boolean shieldAvailable() {
        return ShieldKeys.isAvailable();
    }

    @Test
    @EnabledIf("shieldAvailable")
    void classifiesGoldenAddresses() {
        assertEquals(PivxAddress.AddressType.SHIELD, PivxAddress.validate(SHIELD));
        assertEquals(PivxAddress.AddressType.TRANSPARENT, PivxAddress.validate(TRANSPARENT));
    }

    @Test
    @EnabledIf("shieldAvailable")
    void rejectsCorruptedAndGarbageAddresses() {
        // Flip the last character: bech32 checksum must fail.
        char last = SHIELD.charAt(SHIELD.length() - 1);
        String corruptedShield = SHIELD.substring(0, SHIELD.length() - 1)
                + (last == 'n' ? 'm' : 'n');
        assertEquals(PivxAddress.AddressType.INVALID, PivxAddress.validate(corruptedShield));

        // "ps" prefix alone is not a shield address (the prefix-only
        // isShieldDestination() check would wave this through).
        assertEquals(PivxAddress.AddressType.INVALID, PivxAddress.validate("ps1notanaddress"));

        // Broken base58 checksum on the transparent side.
        String corruptedTransparent = TRANSPARENT.substring(0, TRANSPARENT.length() - 1)
                + (TRANSPARENT.endsWith("J") ? "K" : "J");
        assertEquals(PivxAddress.AddressType.INVALID, PivxAddress.validate(corruptedTransparent));

        assertEquals(PivxAddress.AddressType.INVALID, PivxAddress.validate("garbage"));
        assertEquals(PivxAddress.AddressType.INVALID, PivxAddress.validate(""));
        assertEquals(PivxAddress.AddressType.INVALID, PivxAddress.validate(null));
    }
}
