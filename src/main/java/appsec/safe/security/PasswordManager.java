package appsec.safe.security;

import appsec.safe.config.AppSecProperties;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.springframework.stereotype.Component;

@Component
public class PasswordManager {

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String PHC_PREFIX = "$argon2id$v=19$";
    private static final Base64.Encoder B64_ENCODER = Base64.getEncoder().withoutPadding();
    private static final Base64.Decoder B64_DECODER = Base64.getDecoder();

    private final byte[] pepper;

    public PasswordManager(AppSecProperties properties) {
        String configuredPepper = properties.getPepper();
        if (configuredPepper == null || configuredPepper.length() < 16) {
            throw new IllegalStateException("appsec.pepper must be set (min. 16 characters).");
        }
        this.pepper = configuredPepper.getBytes(StandardCharsets.UTF_8);
    }

    private static final int MIN_LENGTH = 8;
    private static final int MAX_LENGTH = 30;

    private static final int SALT_LENGTH = 16;
    private static final int HASH_LENGTH = 32;
    private static final int ITERATIONS = 3;
    private static final int MEMORY_KB = 65536; // 64 MB
    private static final int PARALLELISM = 1;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public enum StrengthLevel {
        WEAK,
        MEDIUM,
        STRONG,
        VERY_STRONG
    }

    public record ValidationResult(boolean valid, List<String> errors) {
        public static ValidationResult ok() {
            return new ValidationResult(true, List.of());
        }
    }

    public record StrengthAssessment(int score, StrengthLevel level) {}


    public ValidationResult validate(String password, String username, String email) {
        List<String> errors = new ArrayList<>();

        if (password == null) {
            errors.add("Hasło jest wymagane.");
            return new ValidationResult(false, errors);
        }

        if (password.length() < MIN_LENGTH || password.length() > MAX_LENGTH) {
            errors.add("Hasło musi mieć od " + MIN_LENGTH + " do " + MAX_LENGTH + " znaków.");
        }
        if (!password.chars().anyMatch(Character::isUpperCase)) {
            errors.add("Hasło musi zawierać co najmniej jedną wielką literę.");
        }
        if (!password.chars().anyMatch(Character::isLowerCase)) {
            errors.add("Hasło musi zawierać co najmniej jedną małą literę.");
        }
        if (!password.chars().anyMatch(Character::isDigit)) {
            errors.add("Hasło musi zawierać co najmniej jedną cyfrę.");
        }

        String lowerPass = password.toLowerCase(Locale.ROOT);
        if (username != null && !username.isBlank() && lowerPass.contains(username.toLowerCase(Locale.ROOT))) {
            errors.add("Hasło nie może zawierać nazwy użytkownika.");
        }
        if (email != null && !email.isBlank()) {
            String lowerEmail = email.toLowerCase(Locale.ROOT);
            if (lowerPass.contains(lowerEmail)) {
                errors.add("Hasło nie może zawierać adresu e-mail.");
            }
            int atIdx = lowerEmail.indexOf('@');
            if (atIdx > 2) {
                String localPart = lowerEmail.substring(0, atIdx);
                if (lowerPass.contains(localPart)) {
                    errors.add("Hasło nie może zawierać części e-maila przed '@'.");
                }
            }
        }

        return new ValidationResult(errors.isEmpty(), errors);
    }


    public StrengthAssessment evaluateStrength(String password, String username, String email) {
        if (password == null || password.isEmpty()) {
            return new StrengthAssessment(0, StrengthLevel.WEAK);
        }

        int score = 0;


        if (password.length() >= 8) score += 15;
        if (password.length() >= 12) score += 10;
        if (password.length() >= 16) score += 10;

        boolean hasLower = password.chars().anyMatch(Character::isLowerCase);
        boolean hasUpper = password.chars().anyMatch(Character::isUpperCase);
        boolean hasDigit = password.chars().anyMatch(Character::isDigit);
        boolean hasSpecial = password.chars().anyMatch(ch -> !Character.isLetterOrDigit(ch));

        if (hasLower) score += 10;
        if (hasUpper) score += 10;
        if (hasDigit) score += 10;
        if (hasSpecial) score += 10;

        String lowerPass = password.toLowerCase(Locale.ROOT);
        boolean containsUserOrEmail =
                (username != null && !username.isBlank() && lowerPass.contains(username.toLowerCase(Locale.ROOT)))
                        || (email != null && !email.isBlank() && lowerPass.contains(email.toLowerCase(Locale.ROOT)));

        if (!containsUserOrEmail) {
            score += 15;
        }
        if (!hasRepeatedRun(password, 3)) {
            score += 10;
        }

        score = Math.min(100, Math.max(0, score));

        StrengthLevel level;
        if (score < 40) {
            level = StrengthLevel.WEAK;
        } else if (score < 65) {
            level = StrengthLevel.MEDIUM;
        } else if (score < 85) {
            level = StrengthLevel.STRONG;
        } else {
            level = StrengthLevel.VERY_STRONG;
        }

        return new StrengthAssessment(score, level);
    }

    public String hash(String plainPassword) {
        if (plainPassword == null || plainPassword.isEmpty()) {
            throw new IllegalArgumentException("Hasło do zahashowania nie może być puste.");
        }

        byte[] peppered = hmacWithPepper(plainPassword);
        byte[] salt = new byte[SALT_LENGTH];
        SECURE_RANDOM.nextBytes(salt);

        byte[] derivedKey = computeArgon2id(peppered, salt, MEMORY_KB, ITERATIONS, PARALLELISM, HASH_LENGTH);
        // Standard PHC string: $argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>
        return PHC_PREFIX + "m=" + MEMORY_KB + ",t=" + ITERATIONS + ",p=" + PARALLELISM
                + "$" + B64_ENCODER.encodeToString(salt)
                + "$" + B64_ENCODER.encodeToString(derivedKey);
    }

    /**
     * Verifies a password against a stored PHC string. Parameters are read from the
     * stored value, so cost settings can be raised later without breaking old hashes.
     */
    public boolean verify(String plainPassword, String storedHash) {
        if (plainPassword == null || storedHash == null || !storedHash.startsWith(PHC_PREFIX)) {
            return false;
        }

        String[] parts = storedHash.substring(PHC_PREFIX.length()).split("\\$");
        if (parts.length != 3) {
            return false;
        }

        int memory;
        int iterations;
        int parallelism;
        byte[] salt;
        byte[] expectedHash;
        try {
            String[] params = parts[0].split(",");
            if (params.length != 3) {
                return false;
            }
            memory = Integer.parseInt(params[0].substring("m=".length()));
            iterations = Integer.parseInt(params[1].substring("t=".length()));
            parallelism = Integer.parseInt(params[2].substring("p=".length()));
            salt = B64_DECODER.decode(parts[1]);
            expectedHash = B64_DECODER.decode(parts[2]);
        } catch (IllegalArgumentException | IndexOutOfBoundsException ex) {
            return false;
        }

        byte[] peppered = hmacWithPepper(plainPassword);
        byte[] actualHash = computeArgon2id(peppered, salt, memory, iterations, parallelism, expectedHash.length);
        return MessageDigest.isEqual(expectedHash, actualHash);
    }

    private byte[] computeArgon2id(byte[] input, byte[] salt, int memoryKb, int iterations,
                                   int parallelism, int hashLength) {
        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withSalt(salt)
                .withIterations(iterations)
                .withMemoryAsKB(memoryKb)
                .withParallelism(parallelism)
                .build();

        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(params);

        byte[] out = new byte[hashLength];
        generator.generateBytes(input, out, 0, out.length);
        return out;
    }

    /** HMAC-SHA256 with a server-side secret (pepper), kept outside the database. */
    private byte[] hmacWithPepper(String input) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(pepper, HMAC_ALGORITHM));
            return mac.doFinal(input.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("HMAC-SHA256 is not available in this JVM.", ex);
        }
    }

    private boolean hasRepeatedRun(String value, int runLength) {
        int count = 1;
        for (int i = 1; i < value.length(); i++) {
            if (value.charAt(i) == value.charAt(i - 1)) {
                count++;
                if (count >= runLength) {
                    return true;
                }
            } else {
                count = 1;
            }
        }
        return false;
    }
}