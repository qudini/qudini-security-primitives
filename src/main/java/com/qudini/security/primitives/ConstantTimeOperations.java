package com.qudini.security.primitives;

import javax.annotation.CheckReturnValue;
import javax.annotation.ParametersAreNonnullByDefault;
import java.util.Objects;

import static com.qudini.security.primitives.Shredding.shred;
import static java.lang.Math.max;
import static java.util.Arrays.asList;

@CheckReturnValue
@ParametersAreNonnullByDefault
public final class ConstantTimeOperations {

    private ConstantTimeOperations() {
        throw new UnsupportedOperationException();
    }

    /**
     * NOP with some actual computations; create false data dependency with iterations argument and return value to
     * reduce likelihood of javac optimising it away.
     * <p>
     * Suitable as a building block for other constant-time operations which can avoid timing attacks.
     */
    public static byte nop(final long iterations) {
        if (iterations < 0) {
            throw new IllegalArgumentException("iterations must be a positive number");
        }

        long n = iterations;
        byte x = (byte) (n & 1L);
        for (; n != 0; --n) {
            x = (byte) ((n % 2) ^ x);
        }
        if (x == 1) {
            --x;
        }
        return x;
    }

    /**
     * Checks whether two character arrays are equal; guaranteed to run in constant time with at least
     * {@code minElementChecks}. Suitable for avoiding timing attacks.
     */
    public static boolean equals(final char[] xs, final char[] ys, final int minElementChecks) {
        return equals(
                new NonCopyingCharArraySequencer(xs),
                new NonCopyingCharArraySequencer(ys),
                minElementChecks
        );
    }

    /**
     * Checks whether two character arrays are equal; guaranteed to run in constant time with at least
     * {@code minElementChecks}. Suitable for avoiding timing attacks.
     */
    public static boolean equals(final CharSequence xs, final CharSequence ys, final int minElementChecks) {
        Objects.requireNonNull(xs);
        Objects.requireNonNull(ys);

        int result = 0;
        final int xsLength = xs.length();
        final int ysLength = ys.length();
        for (int n = max(xsLength, max(ysLength, max(minElementChecks, 1))) - 1; 0 <= n; --n) {
            final int x = (n < xsLength) ? xs.charAt(n) : -1;
            final int y = (n < ysLength) ? ys.charAt(n) : -1;
            result |= (x ^ y);
        }
        return result == 0;
    }

    /**
     * Do a case-sensitive equality check in constant time to avoid timing attacks, and shred the intermediate arrays
     * used for normalising the case.
     */
    public static boolean caseInsensitiveEquals(final char[] xs, final char[] ys, final int minElementChecks) {
        return caseInsensitiveEquals(
                new NonCopyingCharArraySequencer(xs),
                new NonCopyingCharArraySequencer(ys),
                minElementChecks
        );
    }

    /**
     * Checks whether two character arrays are equal; guaranteed to run in constant time with at least minElementChecks.
     * Suitable for avoiding timing attacks.
     */
    public static boolean equals(final byte[] xs, final byte[] ys, final int minElementChecks) {
        Objects.requireNonNull(xs);
        Objects.requireNonNull(ys);

        int result = 0;
        final int xsLength = xs.length;
        final int ysLength = ys.length;
        for (int n = max(xsLength, max(ysLength, max(minElementChecks, 1))) - 1; 0 <= n; --n) {
            final short x = (n < xsLength) ? xs[n] : -1;
            final short y = (n < ysLength) ? ys[n] : -1;
            result |= (x ^ y);
        }

        return result == 0;
    }

    /**
     * Do a case-sensitive equality check in constant time to avoid timing attacks, and shred the intermediate arrays
     * used for normalising the case.
     */
    public static boolean caseInsensitiveEquals(
            final CharSequence xs,
            final CharSequence ys,
            final int minElementChecks
    ) {
        final char[] lowerXs = new char[xs.length()];
        final char[] lowerYs = new char[ys.length()];

        asList(lowerXs, lowerYs).forEach(chars -> {
            for (int i = chars.length - 1; i != 0; --i) {
                chars[i] = Character.toLowerCase(chars[i]);
            }
        });

        final boolean result = equals(lowerXs, lowerYs, minElementChecks);
        shred(lowerXs);
        shred(lowerYs);
        return result;
    }
}
