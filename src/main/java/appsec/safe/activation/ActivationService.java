package appsec.safe.activation;

import appsec.safe.entity.ActivationTokenEntity;
import appsec.safe.entity.UserEntity;
import appsec.safe.repository.TokenRepository;
import appsec.safe.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class ActivationService {

    private final TokenRepository tokenRepository;
    private final UserRepository userRepository;

    @Transactional
    public void activate(String rawToken) {
        String hash = TokenUtil.sha256(rawToken);

        ActivationTokenEntity token = tokenRepository.findByTokenHash(hash)
                .orElseThrow(ActivationService::invalid);

        if (!token.isValid() || token.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw invalid();
        }

        UserEntity user = token.getUser();
        user.setActive(true);
        token.setValid(false);

        userRepository.save(user);
        tokenRepository.save(token);
    }

    // TODO specific exceptions
    private static ResponseStatusException invalid() {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired link.");
    }
}
