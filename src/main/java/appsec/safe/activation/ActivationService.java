package appsec.safe.activation;

import appsec.safe.activation.token.TokenUtil;
import appsec.safe.activation.token.exception.AlreadyUsedActivationTokenException;
import appsec.safe.activation.token.exception.ExpiredActivationTokenException;
import appsec.safe.activation.token.exception.InvalidActivationTokenException;
import appsec.safe.common.config.AppSecProperties;
import appsec.safe.email.EmailService;
import appsec.safe.entity.ActivationTokenEntity;
import appsec.safe.entity.UserEntity;
import appsec.safe.repository.TokenRepository;
import appsec.safe.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Locale;

@Service
@RequiredArgsConstructor
public class ActivationService {

    private final TokenRepository tokenRepository;
    private final UserRepository userRepository;
    private final EmailService emailService;

    private final AppSecProperties props;

    @Transactional
    public void activate(String rawToken) {
        String hash = TokenUtil.sha256(rawToken);

        ActivationTokenEntity token = tokenRepository.findByTokenHash(hash)
                .orElseThrow(InvalidActivationTokenException::new);

        if (!token.isValid()) {
            throw new AlreadyUsedActivationTokenException();
        }

        if (token.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new ExpiredActivationTokenException();
        }

        UserEntity user = token.getUser();
        user.setActive(true);
        token.setValid(false);

        userRepository.save(user);
        tokenRepository.save(token);
    }

    @Transactional
    public void resendLink(String email) {
        String normalized = email == null ? "" : email.trim().toLowerCase(Locale.ROOT);
        if (normalized.isEmpty() || normalized.length() > 254) {
            return;
        }
        UserEntity user = userRepository.findByEmail(normalized)
                .filter(u -> !u.isActive())
                .orElse(null);
        if (user == null) {
            return;
        }

        AppSecProperties.Activation cfg = props.getActivation();
        LocalDateTime now = LocalDateTime.now();

        // resend-cooldown-minutes: wait after the previous link
        boolean tooSoon = tokenRepository.findTopByUserOrderByCreatedAtDesc(user)
                .map(last -> last.getCreatedAt().isAfter(now.minusMinutes(cfg.getResendCooldownMinutes())))
                .orElse(false);
        if (tooSoon) {
            return;
        }

        // max-tokens-per-user-per-day: counted over the last 24 hours
        long sentToday = tokenRepository.countByUserAndCreatedAtAfter(user, now.minusDays(1));
        if (sentToday >= cfg.getMaxTokensPerUserPerDay()) {
            return;
        }

        tokenRepository.findAllByUserAndValidTrue(user).forEach(t -> t.setValid(false));

        String rawToken = TokenUtil.newToken();
        tokenRepository.save(ActivationTokenEntity.builder()
                .tokenHash(TokenUtil.sha256(rawToken))
                .user(user)
                .email(user.getEmail())
                .createdAt(now)
                .expiresAt(now.plusMinutes(cfg.getTokenTtlMinutes()))
                .build());

        emailService.sendActivationEmail(user.getEmail(), rawToken);
    }
}
