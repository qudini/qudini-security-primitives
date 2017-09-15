package com.qudini.security.primitives;

import javax.annotation.ParametersAreNonnullByDefault;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

@ParametersAreNonnullByDefault
public final class Shredding {

    private Shredding() {
        throw new UnsupportedOperationException();
    }

    /**
     * Shreds an array of bytes. This overwrites mutable bytes with
     * zeros and then random characters from a CSPRNG.
     * <p>
     * While this secures it in the context of the JVM, it does not make any
     * guarantees at the OS memory-management level, which is undoable without
     * low-level unsafe and undocumented JRE APIs.
     */
    public static void shred(final byte[] bytes) {
        Objects.requireNonNull(bytes);

        Arrays.fill(bytes, (byte) 0);
        final int maxByte = Byte.MAX_VALUE;
        final SecureRandom random = new SecureRandom();
        for (int i = bytes.length - 1; i != 0; --i) {

            // Truncating to a byte directly from random.nextInt() would
            // create a distribution with an uneven likelihood of
            // Character.MAX_VALUE.
            bytes[i] = (byte) (random.nextInt() % maxByte);
        }
    }

    /**
     * Shreds an array of characters. This overwrites mutable chars with
     * zeros and then random characters from a CSPRNG.
     * <p>
     * While this secures it in the context of the JVM, it does not make any
     * guarantees at the OS memory-management level, which is undoable without
     * low-level unsafe and undocumented JRE APIs.
     */
    public static void shred(final char[] chars) {
        Objects.requireNonNull(chars);

        Arrays.fill(chars, '\0');
        final int maxChar = (int) Character.MAX_VALUE;
        final SecureRandom random = new SecureRandom();
        for (int i = chars.length - 1; i != 0; --i) {

            // Truncating to a char directly from random.nextInt() would
            // create a distribution with an uneven likelihood of
            // Character.MAX_VALUE.
            chars[i] = (char) (random.nextInt() % maxChar);
        }
    }

    /**
     * Shreds a StringBuilder of characters. This overwrites mutable chars with
     * zeros and then random characters from a CSPRNG.
     * <p>
     * This only shreds it as well as the java.lang.StringBuilder#setCharAt method actually writes over the character in
     * memory.
     */
    public static void shred(final StringBuilder builder) {
        Objects.requireNonNull(builder);

        for (int i = builder.length() - 1; i != 0; --i) {
            builder.setCharAt(i, '\0');
        }

        final int maxChar = (int) Character.MAX_VALUE;
        final SecureRandom random = new SecureRandom();
        for (int i = builder.length() - 1; i != 0; --i) {

            // Truncating to a char directly from random.nextInt() would
            // create a distribution with an uneven likelihood of
            // Character.MAX_VALUE.
            builder.setCharAt(i, (char) (random.nextInt() % maxChar));
        }
    }
}
