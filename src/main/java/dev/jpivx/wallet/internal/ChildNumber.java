package dev.jpivx.wallet.internal;

public class ChildNumber implements Comparable<ChildNumber> {
    public static final int HARDENED_BIT = 0x80000000;
    public static final ChildNumber ZERO = new ChildNumber(0, false);
    public static final ChildNumber ZERO_HARDENED = new ChildNumber(0, true);

    private final int i;

    public ChildNumber(int childNumber, boolean hardened) {
        if ((childNumber & HARDENED_BIT) != 0) {
            throw new IllegalArgumentException("Most significant bit must not be set");
        }
        this.i = hardened ? (childNumber | HARDENED_BIT) : childNumber;
    }

    public ChildNumber(int i) {
        this.i = i;
    }

    public int getI() {
        return i;
    }

    public boolean isHardened() {
        return (i & HARDENED_BIT) != 0;
    }

    public int num() {
        return i & (~HARDENED_BIT);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ChildNumber that = (ChildNumber) o;
        return i == that.i;
    }

    @Override
    public int hashCode() {
        return i;
    }

    @Override
    public int compareTo(ChildNumber other) {
        return Integer.compare(this.i, other.i);
    }

    @Override
    public String toString() {
        return String.format("%d%s", num(), isHardened() ? "'" : "");
    }
}
