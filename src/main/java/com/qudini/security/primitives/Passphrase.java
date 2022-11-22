package com.qudini.security.primitives;

import com.password4j.Hash;
import com.password4j.Password;
import com.password4j.ScryptFunction;

import javax.annotation.CheckReturnValue;
import javax.annotation.Nonnull;
import javax.annotation.ParametersAreNonnullByDefault;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.lang.Math.max;

/**
 * Stores a confirmed passphrase; once stored, only one thing can be done with it: comparing with other passphrases.
 * The passphrase is properly shredded once released as a resource.
 */
@ParametersAreNonnullByDefault
public final class Passphrase implements AutoCloseable {

    private static final int MINIMUM_PASSPHRASE_LENGTH = 8;

    private static final int SALT_SIZE = 64;
    private Optional<char[]> chars;

    private Passphrase(final char[] chars) {
        this.chars = Optional.of(chars);
    }

    /**
     * Store a passphrase that has been confirmed; the check is done with at least <code>minElementChecks</code> checks
     * to avoid timing attacks.
     * <p>
     * Using the constructors that take strings is not encouraged because they cannot be properly shredded.
     * <p>
     * Ownership is taken of passphrase and confirmation, shredding them when no longer used. Even if the passphrases
     * do not match or validation fails, both the passphrase and confirmation are shredded.
     */
    @Nonnull
    @CheckReturnValue
    public static Passphrase create(final char[] passphrase) {
        try {
            final Passphrase pass = new Passphrase(passphrase);

            if (!pass.meetsComplexityRequirements()) {
                throw new InvalidPassphraseException();
            }

            return pass;
        } catch (final InvalidPassphraseException | ConfirmationDoesNotMatchException exception) {
            Shredding.shred(passphrase);
            throw exception;
        }
    }

    @Nonnull
    @CheckReturnValue
    public static Passphrase create(final String passphrase) {
        return create(passphrase.toCharArray());
    }

    @Nonnull
    public static Passphrase confirm(final char[] passphrase, final char[] confirmation, final int minElementChecks) {
        try {
            if (!ConstantTimeOperations.equals(passphrase, confirmation, minElementChecks)) {
                throw new ConfirmationDoesNotMatchException();
            }
            return create(passphrase);
        } finally {

            // If the user provided the same char array for both the passphrase and the confirmation, don't shred it
            // as the passphrase characters are still needed.
            if (confirmation != passphrase) {
                Shredding.shred(confirmation);
            }
        }
    }

    /**
     * Create a passphrase that does not contain the specified username.
     * @see #confirm(char[], char[], int)
     */
    @Nonnull
    public static Passphrase confirm(
            final char[] passphrase,
            final char[] confirmation,
            final int minElementChecks,
            final String userName
    ) {
        if (containsUsername(userName, passphrase)) {
            throw new InvalidPassphraseException();
        }
        return confirm(passphrase, confirmation, minElementChecks);
    }

    /**
     * Create a passphrase derived from a string; not recommended as it involves immutable strings, which cannot be
     * shredded. Confirm that it does not contain the specified username.
     *
     * @see #confirm(char[], char[], int)
     */
    @Nonnull
    public static Passphrase confirm(
            final String passphrase,
            final String confirmation,
            final int minElementChecks,
            final String userName
    ) {
        return confirm(passphrase.toCharArray(), confirmation.toCharArray(), minElementChecks, userName);
    }

    @Nonnull
    public static Passphrase confirm(final String passphrase, final String confirmation, final int minElementChecks) {
        return confirm(passphrase.toCharArray(), confirmation.toCharArray(), minElementChecks);
    }

    @Nonnull
    @CheckReturnValue
    public static Passphrase create(final String passphrase, final String userName) {
        if (containsUsername(userName, passphrase)) {
            throw new InvalidPassphraseException();
        }
        return create(passphrase);
    }

    @Nonnull
    @CheckReturnValue
    public static Passphrase create(final char[] passphrase, final String userName) {
        return create(new String(passphrase), userName);
    }

    /**
     * Store a passphrase that is neither confirmed nor checked for complexity. This is for passphrase attempts, not the
     * creation of new passphrases.
     */
    @Nonnull
    @CheckReturnValue
    public static Passphrase attempt(final char[] passphrase) {
        return new Passphrase(passphrase);
    }

    /**
     * Attempt a passphrase derived from a string; not recommended as it involves immutable strings, which cannot be
     * shredded.
     *
     * @see #attempt(char[])
     */
    @Nonnull
    @CheckReturnValue
    public static Passphrase attempt(final String passphrase) {
        return attempt(passphrase.toCharArray());
    }

    @CheckReturnValue
    private static boolean hasMinimumLength(final String passphrase) {
        return MINIMUM_PASSPHRASE_LENGTH <= passphrase.length();
    }

    @CheckReturnValue
    private static boolean isMulticaseAlphaAndNumeric(final String passphrase) {
        return Stream
                .of(".*?[a-z]+.*", ".*?[A-Z]+.*", ".*?\\d+.*")
                .reduce(
                        true,
                        (successfulSoFar, regexp) -> successfulSoFar && Pattern.matches(regexp, passphrase),
                        Boolean::logicalAnd
                );
    }

    @CheckReturnValue
    private static boolean isInternational(final String passphrase) {

        // TODO: this is a hacky regexp; rework it. What if an international passphrase has spaces, for example?
        return Pattern.matches("^[^\\w\\s\\d]+$", passphrase);
    }

    @CheckReturnValue
    private static boolean containsUsername(final String userName, final char[] passphrase) {
        return new String(passphrase).toLowerCase().contains(userName.toLowerCase());
    }

    @CheckReturnValue
    private static boolean containsUsername(final String userName, final String passphrase) {
        return containsUsername(userName, passphrase.toCharArray());
    }

    @Nonnull
    @CheckReturnValue
    private static byte[] generateBase64() {
        final byte[] bytes = new byte[SALT_SIZE];

        final SecureRandom random = new SecureRandom();
        random.nextBytes(bytes);

        return Base64.getEncoder().encode(bytes);
    }

    @Nonnull
    @CheckReturnValue
    public static Passphrase generateRandom(final int minElementChecks) {
        final int m = 30;
        for (int n = 0; n < m; ++n) {
            try {
                final char[] random = new String(generateBase64(), Charset.forName("ascii")).toCharArray();
                return confirm(random, random, minElementChecks);
            } catch (final InvalidPassphraseException | ConfirmationDoesNotMatchException exception) {
            }
        }

        throw new IllegalStateException(
                "random passphrase generation failed validation "
                        + m
                        + " times, which is _very_ unlikely without a programmer error"
        );
    }

    @CheckReturnValue
    public boolean meetsComplexityRequirements() {

        /*
         * TODO: make a passphrase complexity checker that works with char arrays, otherwise the char shredding is
         * ineffective.
         */
        return asStringForLegacyAuthentication()
                .map(string ->
                        hasMinimumLength(string)
                                && (isMulticaseAlphaAndNumeric(string) || isInternational(string))
                ).orElse(false);
    }

    /**
     * Shred the underlying passphrase, and invalidate it for other operations.
     */
    public void close() {
        chars = chars.flatMap(presentChars -> {
            Shredding.shred(presentChars);
            return Optional.empty();
        });
    }

    /**
     * Checks two passphrases against each other. <em>Use the overload with minElementChecks if a minimum amount of
     * elements checks is needed to avoid timing attacks.</em>
     */
    @Override
    public boolean equals(final Object that) {
        if (!(that instanceof Passphrase)) {
            return false;
        }
        final Passphrase passphrase = (Passphrase) that;

        Stream.of(chars, passphrase.chars).forEach(x -> x.orElseThrow(PassphraseShreddedException::new));

        return equals(passphrase, max(chars.get().length, passphrase.chars.get().length));
    }

    @Override
    public int hashCode() {
        return chars.hashCode();
    }

    /**
     * Hash the passphrase using the specified algorithm; base64 the result to reduce corner cases in persistent storage
     * and data transmission.
     */
    @Nonnull
    @CheckReturnValue
    public byte[] hash(
            final byte[] salt,
            final byte[] pepper,
            final long processorCost,
            final long memoryCost,
            final int parallelisationParameter,
            final int derivedKeyLength
    ) {

        final char[] charArray = chars.orElseThrow(PassphraseShreddedException::new);

        if (salt.length < charArray.length) {
            throw new SaltNotLongEnoughException();
        }
        if (pepper.length < 32) {
            throw new PepperNotLongEnoughException();
        }

        if (Stream.of(processorCost, memoryCost, parallelisationParameter, derivedKeyLength).anyMatch(
                (Number x) -> x.doubleValue() < 1)
        ) {
            throw new InvalidCipherParameterArgumentException();
        }

        final byte[] hashingSalt = new byte[salt.length + pepper.length];
        System.arraycopy(salt, 0, hashingSalt, 0, salt.length);
        System.arraycopy(pepper, 0, hashingSalt, salt.length, pepper.length);

        Hash hash = Password.hash(String.valueOf(charArray))
                .addSalt(new String(hashingSalt)) // use this for backwards compat rather than .addSalt(...).addPepper(...)
                .with(ScryptFunction.getInstance((int) processorCost, (int) memoryCost, parallelisationParameter, derivedKeyLength));

        return Base64.getEncoder().encode(hash.getBytes());

    }

    /**
     * <strong>Only use for compatibility with APIs that force passphrases to be used as strings; this breaks the
     * shredding mechanism.</strong>
     * <p>
     * The return value will only be empty if the password has been closed as a resource, leading the password to be
     * shredded.
     */
    @Nonnull
    @CheckReturnValue
    public Optional<String> asStringForLegacyAuthentication() {
        return chars.map(String::valueOf);
    }

    /**
     * Checks two passphrase against each other in constant time, using at least minElementChecks element checks.
     */
    @CheckReturnValue
    public boolean equals(final Passphrase that, final int minElementChecks) {
        final List<char[]> passphrases = Stream
                .of(this, that)
                .map(passphrase -> passphrase.chars.orElseThrow(PassphraseShreddedException::new))
                .collect(Collectors.toList());

        return ConstantTimeOperations.equals(passphrases.get(0), passphrases.get(1), minElementChecks);
    }

    public static class InvalidPassphraseException extends RuntimeException {
    }

    public static class SaltNotLongEnoughException extends RuntimeException {
    }

    public static class PepperNotLongEnoughException extends RuntimeException {
    }

    public static class InvalidCipherParameterArgumentException extends RuntimeException {
    }

    public static class ConfirmationDoesNotMatchException extends RuntimeException {
    }

    public static class PassphraseShreddedException extends RuntimeException {
    }
}