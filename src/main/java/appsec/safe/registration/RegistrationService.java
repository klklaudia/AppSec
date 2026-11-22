package appsec.safe.registration;

import appsec.safe.email.EmailService;
import appsec.safe.activation.TokenUtil;
import appsec.safe.entity.ActivationTokenEntity;
import appsec.safe.entity.UserEntity;
import appsec.safe.repository.TokenRepository;
import appsec.safe.repository.UserRepository;
import appsec.safe.security.PasswordManager;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Locale;

@Service
@RequiredArgsConstructor
public class RegistrationService {

    private static final String DEFAULT_ROLE = "USER";

    private final UserRepository userRepository;
    private final PasswordManager passwordManager;
    private final TokenRepository tokenRepository;
    private final EmailService emailService;

    @Value("${appsec.activation.token-ttl-minutes}")
    private long tokenTtlMinutes;

    //TODO decide, if RegistrationResult is needed
    @Transactional
    public RegistrationResult register(RegisterRequest request) {
        String username = request.username().trim();
        String email = request.email().trim().toLowerCase(Locale.ROOT);

        PasswordManager.ValidationResult passwordCheck =
                passwordManager.validate(request.password(), username, email);
        if (!passwordCheck.valid()) {
            throw new RegistrationException(HttpStatus.BAD_REQUEST, passwordCheck.errors());
        }

        // Draft "almost happy path": same username + e-mail of an inactive account.
        userRepository.findByUsernameAndEmail(username, email)
                .filter(existing -> !existing.isActive())
                .ifPresent(existing -> {
                    throw new RegistrationException(HttpStatus.CONFLICT,
                            "This account already exists but has not been activated yet.");
                }); //TODO resend the token
        if (userRepository.existsByUsername(username)) {
            throw new RegistrationException(HttpStatus.CONFLICT, "Username is already taken.");
        }
        if (userRepository.existsByEmail(email)) {
            throw new RegistrationException(HttpStatus.CONFLICT, "E-mail address is already in use.");
        }

        UserEntity user = UserEntity.builder()
                .username(username)
                .email(email)
                .hashedPassword(passwordManager.hash(request.password()))
                .active(false)
                .build();

        try {
            UserEntity saved = userRepository.saveAndFlush(user);

            String rawToken = TokenUtil.newToken();
            LocalDateTime now = LocalDateTime.now();
            tokenRepository.save(ActivationTokenEntity.builder()
                    .tokenHash(TokenUtil.sha256(rawToken))
                    .user(saved)
                    .email(saved.getEmail())
                    .createdAt(now)
                    .expiresAt(now.plusMinutes(tokenTtlMinutes))
                    .build());
            emailService.sendActivationEmail(saved.getEmail(), rawToken);

            return new RegistrationResult(saved, rawToken);
        } catch (DataIntegrityViolationException ex) {
            // Race between the exists-checks above and the insert; UNIQUE constraints decide.
            throw new RegistrationException(HttpStatus.CONFLICT, "Username or e-mail address is already in use.");
        }
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
