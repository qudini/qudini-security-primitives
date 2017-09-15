package com.qudini.security.primitives;

/**
 * Provide a sequence over a char array. Do <em>not</em> copy the underlying array even for subsequencing, as the array
 * may have sensitive data that will be shredded after use.
 */
public final class NonCopyingCharArraySequencer implements CharSequence {

    private final int start;
    private final int end;
    private final char[] chars;

    /**
     * Provide a CharSequence over <code>chars</code>. Nothing is done to chars except the sequencing; for example, if
     * the data must shredded, you must invoke helpers.Security#shredChars manually afterwards.
     */
    public NonCopyingCharArraySequencer(final char[] chars) {
        this(chars, 0, chars.length);
    }

    private NonCopyingCharArraySequencer(final char[] chars, final int start, final int end) {
        if (end < start) {
            throw new IllegalArgumentException("the start index cannot be less than the end index");
        }

        this.start = start;
        this.end = end;
        this.chars = chars;
    }

    @Override
    public int length() {
        return end - start;
    }

    @Override
    public char charAt(int index) {
        return chars[start + index];
    }

    @Override
    public CharSequence subSequence(int start, int end) {
        return new NonCopyingCharArraySequencer(chars, start, end);
    }
}
