package appsec.safe.repository;

import appsec.safe.entity.ActivationTokenEntity;
import appsec.safe.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<ActivationTokenEntity, Integer> {
    Optional<ActivationTokenEntity> findByTokenHash(String tokenHash);
    Optional<ActivationTokenEntity> findTopByUserOrderByCreatedAtDesc(UserEntity user);
    long countByUserAndCreatedAtAfter(UserEntity user, LocalDateTime since);
    List<ActivationTokenEntity> findAllByUserAndValidTrue(UserEntity user);
}