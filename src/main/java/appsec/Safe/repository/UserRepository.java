package appsec.Safe.repository;

import appsec.Safe.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<UserEntity, Integer> {
    boolean existsByUsername(String username);
    boolean existsByEmail(String email);
    Optional<UserEntity> findByUsername(String username);
    Optional<UserEntity> findByEmail(String email);
    Optional<UserEntity> findByUsernameAndEmail(String username, String email);
}