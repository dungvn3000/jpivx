package dev.jpivx.wallet.internal;

import java.util.Arrays;

public class Base58 {
    public static final char[] ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();
    private static final char ENCODED_ZERO = ALPHABET[0];
    private static final int[] INDEXES = new int[128];
    static {
        Arrays.fill(INDEXES, -1);
        for (int i = 0; i < ALPHABET.length; i++) {
            INDEXES[ALPHABET[i]] = i;
        }
    }

    public static String encode(byte[] input) {
        if (input.length == 0) return "";
        int zeros = 0;
        while (zeros < input.length && input[zeros] == 0) ++zeros;
        byte[] inputCopy = Arrays.copyOf(input, input.length);
        char[] encoded = new char[inputCopy.length * 2];
        int outputStart = encoded.length;
        for (int inputStart = zeros; inputStart < inputCopy.length; ) {
            encoded[--outputStart] = ALPHABET[divmod(inputCopy, inputStart, 256, 58)];
            if (inputCopy[inputStart] == 0) ++inputStart;
        }
        while (outputStart < encoded.length && encoded[outputStart] == ENCODED_ZERO) ++outputStart;
        while (--zeros >= 0) encoded[--outputStart] = ENCODED_ZERO;
        return new String(encoded, outputStart, encoded.length - outputStart);
    }

    public static byte[] decode(String input) {
        if (input.isEmpty()) return new byte[0];
        byte[] input58 = new byte[input.length()];
        for (int i = 0; i < input.length(); ++i) {
            char c = input.charAt(i);
            int digit = c < 128 ? INDEXES[c] : -1;
            if (digit < 0) throw new IllegalArgumentException("Invalid Base58 character");
            input58[i] = (byte) digit;
        }
        int zeros = 0;
        while (zeros < input58.length && input58[zeros] == 0) ++zeros;
        byte[] decoded = new byte[input.length()];
        int outputStart = decoded.length;
        for (int inputStart = zeros; inputStart < input58.length; ) {
            decoded[--outputStart] = (byte) divmod(input58, inputStart, 58, 256);
            if (input58[inputStart] == 0) ++inputStart;
        }
        while (outputStart < decoded.length && decoded[outputStart] == 0) ++outputStart;
        return Arrays.copyOfRange(decoded, outputStart - zeros, decoded.length);
    }

    private static int divmod(byte[] number, int firstDigit, int base, int divisor) {
        int remainder = 0;
        for (int i = firstDigit; i < number.length; i++) {
            int digit = (int) number[i] & 0xFF;
            int temp = remainder * base + digit;
            number[i] = (byte) (temp / divisor);
            remainder = temp % divisor;
        }
        return remainder;
    }

    public static String encodeChecked(int version, byte[] payload) {
        byte[] addressBytes = new byte[1 + payload.length + 4];
        addressBytes[0] = (byte) version;
        System.arraycopy(payload, 0, addressBytes, 1, payload.length);
        byte[] checksum = hash256(addressBytes, 0, payload.length + 1);
        System.arraycopy(checksum, 0, addressBytes, payload.length + 1, 4);
        return encode(addressBytes);
    }

    public static byte[] decodeChecked(String input) {
        byte[] decoded = decode(input);
        if (decoded.length < 4) throw new IllegalArgumentException("Input too short");
        byte[] data = Arrays.copyOfRange(decoded, 0, decoded.length - 4);
        byte[] checksum = Arrays.copyOfRange(decoded, decoded.length - 4, decoded.length);
        byte[] actualChecksum = Arrays.copyOfRange(hash256(data, 0, data.length), 0, 4);
        if (!Arrays.equals(checksum, actualChecksum)) throw new IllegalArgumentException("Checksum mismatch");
        return data; // version byte + payload (caller strips version if needed)
    }

    private static byte[] hash256(byte[] input, int offset, int length) {
        byte[] slice = new byte[length];
        System.arraycopy(input, offset, slice, 0, length);
        return ByteUtil.sha256d(slice);
    }
}
