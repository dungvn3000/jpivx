package dev.jpivx.wallet.crypto;

import dev.jpivx.wallet.internal.ChildNumber;
import dev.jpivx.wallet.internal.DeterministicKey;
import dev.jpivx.wallet.internal.HDKeyDerivation;

import java.util.List;

/**
 * BIP32 hierarchical-deterministic key derivation.
 *
 * <p>Thin wrapper around bitcoinj's {@link HDKeyDerivation}. The Rust kit uses
 * the {@code bip32} crate's {@code XPrv::derive_from_path}; bitcoinj implements
 * the same BIP32 standard, so derived keys are byte-identical for the same seed
 * and path.
 */
public final class BIP32Service {

    private BIP32Service() {
        throw new AssertionError("no instances");
    }

    /**
     * Create the BIP32 master private key from a seed (typically the 64-byte
     * BIP39 seed).
     *
     * @param seed 64-byte (or 16/32-byte) BIP39 seed
     * @return master deterministic key
     */
    public static DeterministicKey masterKey(byte[] seed) {
        return HDKeyDerivation.createMasterPrivateKey(seed);
    }

    /**
     * Derive a child key by walking the derivation path from the master key.
     *
     * @param master the master key (from {@link #masterKey})
     * @param path   the path components (e.g. {@code 44'/119'/0'/0/0})
     * @return the derived deterministic key
     */
    public static DeterministicKey derivePath(DeterministicKey master, List<ChildNumber> path) {
        DeterministicKey key = master;
        for (ChildNumber child : path) {
            key = HDKeyDerivation.deriveChildKey(key, child);
        }
        return key;
    }

    /**
     * Derive a child key directly from a seed and a full path.
     */
    public static DeterministicKey deriveFromSeed(byte[] seed, List<ChildNumber> path) {
        return derivePath(masterKey(seed), path);
    }

    /**
     * Build the PIVX transparent-account derivation path
     * {@code m/44'/119'/0'/{change}/{index}}.
     *
     * <p>PIVX uses BIP44 coin type {@code 119} (NOT Bitcoin's {@code 0}).
     *
     * @param change 0 = external/receive, 1 = internal/change
     * @param index  the address index within the change branch
     * @return the path components
     */
    public static List<ChildNumber> pivxTransparentPath(int change, int index) {
        return List.of(
                new ChildNumber(44, true),
                new ChildNumber(dev.jpivx.wallet.core.PivxParams.PIVX_COIN_TYPE, true),
                new ChildNumber(0, true),
                new ChildNumber(change, false),
                new ChildNumber(index, false)
        );
    }
}
