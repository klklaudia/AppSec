package appsec.safe.security;

import appsec.safe.config.AppSecProperties;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PasswordManagerTest {

    private static PasswordManager manager(String pepper) {
        AppSecProperties properties = new AppSecProperties();
        properties.setPepper(pepper);
        return new PasswordManager(properties);
    }

    private final PasswordManager passwordManager = manager("test-pepper-0123456789abcdef");

    @Test
    void hashUsesPhcFormatAndVerifies() {
        String hash = passwordManager.hash("Secret123");

        assertTrue(hash.startsWith("$argon2id$v=19$m=65536,t=3,p=1$"));
        assertTrue(passwordManager.verify("Secret123", hash));
        assertFalse(passwordManager.verify("Secret124", hash));
    }

    @Test
    void sameDataGivesDifferentHashesBecauseOfSalt() {
        assertNotEquals(passwordManager.hash("Secret123"), passwordManager.hash("Secret123"));
    }

    @Test
    void hashFromDifferentPepperDoesNotVerify() {
        String hash = passwordManager.hash("Secret123");

        assertFalse(manager("another-pepper-0123456789").verify("Secret123", hash));
    }

    @Test
    void malformedStoredHashIsRejected() {
        assertFalse(passwordManager.verify("Secret123", "garbage"));
        assertFalse(passwordManager.verify("Secret123", "$argon2id$v=19$m=x,t=3,p=1$abc$def"));
    }

    @Test
    void missingPepperFailsFast() {
        assertThrows(IllegalStateException.class, () -> manager(null));
        assertThrows(IllegalStateException.class, () -> manager("short"));
    }

    @Test
    void validationRulesFromDraft() {
        assertTrue(passwordManager.validate("Secret123", "john", "john@example.com").valid());
        assertFalse(passwordManager.validate("secret123", "john", "john@example.com").valid());
        assertFalse(passwordManager.validate("SECRET123", "john", "john@example.com").valid());
        assertFalse(passwordManager.validate("SecretAbc", "john", "john@example.com").valid());
        assertFalse(passwordManager.validate("Sec1", "john", "john@example.com").valid());
        assertFalse(passwordManager.validate("Johnny123", "john", "x@example.com").valid());
    }
}
