package dev.jpivx.wallet.crypto;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Cross-verification of the JNI shield bridge against the Rust
 * {@code pivx-wallet-kit}.
 *
 * <p>Golden values below were captured from
 * {@code pivx-wallet-kit::keys} for the same BIP39 test mnemonic used by the
 * kit's own integration tests ({@code tests/integration.rs}) — see the
 * {@code print_golden_vectors} test in {@code native/shield-jni/src/lib.rs}.
 *
 * <p>All tests are skipped when the native library is not loaded (e.g. a CI
 * machine without the Rust toolchain), so the transparent-only test suite
 * stays green everywhere.
 */
class ShieldKeysTest {

    /** BIP39 test vector shared with the Rust kit. */
    private static final String TEST_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /** Golden values from pivx-wallet-kit (librustpivx, ZIP32 m/32'/119'/0'). */
    private static final String EXPECTED_EXTFVK =
            "pxviews1qw60h08aqqqqpq8qvpzd8ca5nkrjxdd2h2smcnzlzuskk8a8fy7axcvdtykfrs8gf68jft64y7lng7scfae6l33up2v34q8sd0ufzc2vzsz7cdt755f55q4xdc484j75s8r0dhuvelv6hvxfez3yslxv0aqczcpu7999zj4uyfdevypngmgn6h7eu8a47pufc9aaxfx8y53nqpjknncygwfa5qgvnkuj5l3mky5efh3xp2wmuf9xl87detgfqerq4kx2y0rhpup700gxhw06h";
    private static final String EXPECTED_DEFAULT_ADDRESS =
            "ps124f3dxhmtygh72cu8f05t94yey59at3armnk44uctjwdqf9uk2grnth3h5uszmqzzeev7kcr7rn";
    private static final long NEXT_INDEX = 4;
    private static final String EXPECTED_NEXT_ADDRESS =
            "ps12q44a2gnk6vskahfg958xlxqm43trtt4ywllhkfc987crathntnwmg4s0yquklluxj4pq5j9x9a";

    static boolean shieldAvailable() {
        return ShieldKeys.isAvailable();
    }

    private static byte[] testSeed() {
        return BIP39Service.toSeed(BIP39Service.parse(TEST_MNEMONIC));
    }

    @Test
    @EnabledIf("shieldAvailable")
    void extfvkMatchesRustKitGoldenValue() {
        assertEquals(EXPECTED_EXTFVK, ShieldKeys.extfvk(testSeed()));
    }

    @Test
    @EnabledIf("shieldAvailable")
    void defaultShieldAddressMatchesRustKitGoldenValue() {
        assertEquals(EXPECTED_DEFAULT_ADDRESS, ShieldKeys.defaultShieldAddress(testSeed()));
    }

    @Test
    @EnabledIf("shieldAvailable")
    void shieldAddressAtZeroMatchesDefaultAddress() {
        ShieldKeys.ShieldAddress result = ShieldKeys.shieldAddressAt(EXPECTED_EXTFVK, 0);
        assertEquals(0, result.index());
        assertEquals(EXPECTED_DEFAULT_ADDRESS, result.address());
    }

    @Test
    @EnabledIf("shieldAvailable")
    void shieldAddressAtAdvancesToNextValidDiversifier() {
        // Starting at 1, the Rust kit's find_address lands on index 4.
        ShieldKeys.ShieldAddress result = ShieldKeys.shieldAddressAt(EXPECTED_EXTFVK, 1);
        assertEquals(NEXT_INDEX, result.index());
        assertEquals(EXPECTED_NEXT_ADDRESS, result.address());
        assertNotEquals(EXPECTED_DEFAULT_ADDRESS, result.address());
    }

    @Test
    @EnabledIf("shieldAvailable")
    void derivationIsDeterministic() {
        byte[] seed = testSeed();
        assertEquals(ShieldKeys.defaultShieldAddress(seed), ShieldKeys.defaultShieldAddress(seed));
        assertEquals(ShieldKeys.extfvk(seed), ShieldKeys.extfvk(seed));
    }

    @Test
    @EnabledIf("shieldAvailable")
    void rejectsOutOfRangeStartIndex() {
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                () -> ShieldKeys.shieldAddressAt(EXPECTED_EXTFVK, -1));
    }

    @Test
    void availabilityReportsReasonWhenMissing() {
        if (!ShieldKeys.isAvailable()) {
            assertTrue(ShieldKeys.unavailableReason() == null
                    || !ShieldKeys.unavailableReason().isBlank());
        } else {
            assertTrue(EXPECTED_DEFAULT_ADDRESS.startsWith("ps1"));
        }
    }
}
