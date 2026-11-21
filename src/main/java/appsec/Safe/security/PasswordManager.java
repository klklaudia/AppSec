package appsec.Safe.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.springframework.stereotype.Component;

@Component
public class PasswordManager {

    private static final int MIN_LENGTH = 8;
    private static final int MAX_LENGTH = 30;

    // Parametry Argon2id (dostosowane do lokalnego środowiska dev)
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

        byte[] preHashed = sha256(plainPassword);
        byte[] salt = new byte[SALT_LENGTH];
        SECURE_RANDOM.nextBytes(salt);

        byte[] derivedKey = computeArgon2id(preHashed, salt);
        return Base64.getEncoder().encodeToString(salt) + ":" + Base64.getEncoder().encodeToString(derivedKey);
    }

  
    public boolean verify(String plainPassword, String storedHash) {
        if (plainPassword == null || storedHash == null || !storedHash.contains(":")) {
            return false;
        }

        String[] parts = storedHash.split(":", 2);
        byte[] salt;
        byte[] expectedHash;
        try {
            salt = Base64.getDecoder().decode(parts[0]);
            expectedHash = Base64.getDecoder().decode(parts[1]);
        } catch (IllegalArgumentException ex) {
            return false;
        }

        byte[] preHashed = sha256(plainPassword);
        byte[] actualHash = computeArgon2id(preHashed, salt);
        return MessageDigest.isEqual(expectedHash, actualHash);
    }

    private byte[] computeArgon2id(byte[] input, byte[] salt) {
        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withSalt(salt)
                .withIterations(ITERATIONS)
                .withMemoryAsKB(MEMORY_KB)
                .withParallelism(PARALLELISM)
                .build();

        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(params);

        byte[] out = new byte[HASH_LENGTH];
        generator.generateBytes(input, out, 0, out.length);
        return out;
    }

    private byte[] sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(input.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("Brak algorytmu SHA-256 w środowisku JVM.", ex);
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