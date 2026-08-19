package dev.jpivx.wallet.crypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Port of {@code decode_transparent_address_roundtrips_to_script} from
 * {@code tests/integration.rs}, plus explicit P2PKH script assertions.
 */
class PivxAddressTest {

    @Test
    void addressToP2pkhScriptProducesCanonicalScript() {
        // From the Rust kit's transparent address for the test mnemonic.
        String address = TransparentKeysTest.EXPECTED_ADDRESS;
        byte[] script = PivxAddress.addressToP2pkhScript(address);
        // OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG = 25 bytes.
        assertEquals(25, script.length);
        assertEquals((byte) 0x76, script[0]); // OP_DUP
        assertEquals((byte) 0xa9, script[1]); // OP_HASH160
        assertEquals((byte) 0x14, script[2]); // push 20 bytes
        assertEquals((byte) 0x88, script[23]); // OP_EQUALVERIFY
        assertEquals((byte) 0xac, script[24]); // OP_CHECKSIG
    }

    @Test
    void addressToP2pkhScriptHashMatchesAddressToHash160() {
        String address = TransparentKeysTest.EXPECTED_ADDRESS;
        byte[] script = PivxAddress.addressToP2pkhScript(address);
        byte[] hash160 = PivxAddress.addressToHash160(address);
        // The middle 20 bytes of the script must equal hash160.
        byte[] scriptHash = new byte[20];
        System.arraycopy(script, 3, scriptHash, 0, 20);
        assertArrayEquals(hash160, scriptHash);
    }

    @Test
    void hash160RoundtripsBackToSameAddress() {
        String address = TransparentKeysTest.EXPECTED_ADDRESS;
        byte[] hash160 = PivxAddress.addressToHash160(address);
        String reconstructed = PivxAddress.hash160ToAddress(hash160);
        assertEquals(address, reconstructed);
    }

    @Test
    void pubkeyToPivxAddressProducesDPrefix34Chars() {
        // Synthesise a random compressed pubkey shape and encode — we don't
        // assert a specific value, just the format invariants (prefix + length).
        byte[] pubkey = new byte[]{
                0x02, // compressed, even y
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
        };
        String address = PivxAddress.pubkeyToPivxAddress(pubkey);
        assertEquals(34, address.length());
        assertEquals('D', address.charAt(0));
    }

    @Test
    void addressDecodeRejectsForeignVersionByte() {
        // A checksummed 21-byte payload with a NON-PIVX version byte must be
        // rejected: a Bitcoin ('1...', version 0) address is otherwise a valid
        // Base58Check string and would become an irreversible wrong-chain send.
        byte[] hash160 = PivxAddress.addressToHash160(TransparentKeysTest.EXPECTED_ADDRESS);
        String bitcoinStyle = dev.jpivx.wallet.internal.Base58.encodeChecked(0, hash160);
        assertThrows(IllegalArgumentException.class,
                () -> PivxAddress.addressToP2pkhScript(bitcoinStyle));
        assertThrows(IllegalArgumentException.class,
                () -> PivxAddress.addressToHash160(bitcoinStyle));
    }

    @Test
    void addressToP2pkhScriptRejectsMalformed() {
        // Wrong length after decode — a raw base58 string that decodes to
        // something other than 21 bytes (version + hash). The plain "abc"
        // decodes to 2 bytes, which is != 21.
        assertThrows(IllegalArgumentException.class,
                () -> PivxAddress.addressToP2pkhScript("abc"));
    }
}
