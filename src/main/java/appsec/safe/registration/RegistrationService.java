package appsec.safe.registration;

import appsec.safe.entity.RoleEntity;
import appsec.safe.entity.UserEntity;
import appsec.safe.repository.RoleRepository;
import appsec.safe.repository.UserRepository;
import appsec.safe.security.PasswordManager;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Locale;

@Service
@RequiredArgsConstructor
public class RegistrationService {

    private static final String DEFAULT_ROLE = "USER";

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordManager passwordManager;

    /**
     * Creates a new, inactive account. Activation token generation and e-mail sending
     * are the next step (TODO: ActivationService).
     */
    @Transactional
    public UserEntity register(RegisterRequest request) {
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
                });
        if (userRepository.existsByUsername(username)) {
            throw new RegistrationException(HttpStatus.CONFLICT, "Username is already taken.");
        }
        if (userRepository.existsByEmail(email)) {
            throw new RegistrationException(HttpStatus.CONFLICT, "E-mail address is already in use.");
        }

        RoleEntity role = roleRepository.findByRoleName(DEFAULT_ROLE)
                .orElseThrow(() -> new IllegalStateException("Role " + DEFAULT_ROLE + " is missing."));

        UserEntity user = UserEntity.builder()
                .role(role)
                .username(username)
                .email(email)
                .hashedPassword(passwordManager.hash(request.password()))
                .name(blankToNull(request.name()))
                .surname(blankToNull(request.surname()))
                .birthday(request.birthday())
                .active(false)
                .build();

        try {
            return userRepository.saveAndFlush(user);
        } catch (DataIntegrityViolationException ex) {
            // Race between the exists-checks above and the insert; UNIQUE constraints decide.
            throw new RegistrationException(HttpStatus.CONFLICT, "Username or e-mail address is already in use.");
        }
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
