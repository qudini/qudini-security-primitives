package com.qudini.security.primitives;

import junit.framework.TestCase;

import static java.util.stream.IntStream.range;

/**
 * Unit test for simple App.
 */
public class SecurityPrimitivesTest extends TestCase {

    private final static String userName = "Test User";
    private final static Passphrase passphrase1 = Passphrase.confirm(
            "aBCdef123".toCharArray(),
            "aBCdef123".toCharArray(),
            256
    );
    private final static Passphrase passphrase2 = Passphrase.confirm(
            "aBCdef123".toCharArray(),
            "aBCdef123".toCharArray(),
            256
    );
    private final static Passphrase passphrase3 = Passphrase.confirm(
            "AbcDEF123".toCharArray(),
            "AbcDEF123".toCharArray(),
            256
    );

    private final static Passphrase internationalPassphrase1 = Passphrase.confirm(
            "你好你好你好你好你好".toCharArray(),
            "你好你好你好你好你好".toCharArray(),
            256
    );

    private final static Passphrase internationalPassphrase2 = Passphrase.confirm(
            "你好你好你好你好你好".toCharArray(),
            "你好你好你好你好你好".toCharArray(),
            256
    );

    private final static Passphrase internationalPassphrase3 = Passphrase.confirm(
            "你好你好你好helloHELLOhello1".toCharArray(),
            "你好你好你好helloHELLOhello1".toCharArray(),
            256
    );

    public void testPassphraseWithInvalidConfirmation() {
        try {
            Passphrase.confirm("aBCdef123".toCharArray(), "123456".toCharArray(), 256);
        } catch (final Passphrase.ConfirmationDoesNotMatchException exception) {
            return;
        }
        fail("non matching passphrases did not throw an exception");
    }

    public void testOverlySimplePassphraseRejection() {
        try {
            Passphrase.confirm("abcdef".toCharArray(), "abcdef".toCharArray(), 256);
        } catch (final Passphrase.InvalidPassphraseException exception) {
            return;
        }
        fail("an overly-simple passphrase was not rejected");
    }

    public void testPassphraseEquality() {
        assertTrue(passphrase1.equals(passphrase2));
        assertFalse(passphrase2.equals(passphrase3));

        assertTrue(internationalPassphrase1.equals(internationalPassphrase2));
        assertFalse(internationalPassphrase2.equals(internationalPassphrase3));
    }

    public void testShreddingChangesArray() {
        final char[] manyAs = {
                'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
                'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
                'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
                'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
                'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
                'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
                'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
                'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
                'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
                'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
        };
        final int manyAsLength = manyAs.length;
        Shredding.shred(manyAs);

        assertEquals(manyAs.length, manyAsLength);

        boolean allAs = range(0, manyAs.length)
                .mapToObj(i -> manyAs[i])
                .allMatch(c -> c == 'A');

        // Technically possible in a working algorithm but VERY unlikely.
        assertFalse(allAs);
    }

    public void testNopReturnsZero() {
        assertEquals(0, ConstantTimeOperations.nop(0));
        assertEquals(0, ConstantTimeOperations.nop(10));
        assertEquals(0, ConstantTimeOperations.nop(1000));
        assertEquals(0, ConstantTimeOperations.nop(9999999));
    }

    public void testConstantTimeEqualityCheck() {
        assertTrue(ConstantTimeOperations.equals(new char[]{}, new char[]{}, 0));

        assertTrue(ConstantTimeOperations.equals(
                "ABCDEF".toCharArray(),
                "ABCDEF".toCharArray(),
                "ABCDEF".length()
        ));

        assertTrue(ConstantTimeOperations.equals(
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray(),
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray(),
                99999
        ));

        assertFalse(ConstantTimeOperations.equals(new char[]{}, "ABC".toCharArray(), 10));

        assertFalse(ConstantTimeOperations.equals(
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray(),
                "ABCDEFGHIJKLMNOPQRSTUVWAAA".toCharArray(),
                26
        ));
    }
}
