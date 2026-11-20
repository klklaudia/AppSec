package appsec.Safe.repository;

import appsec.Safe.entity.IncidentTypeEntity;
import appsec.Safe.entity.RegisteredIncidentEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.Optional;

public interface IncidentRepository extends JpaRepository<RegisteredIncidentEntity, Integer> {
    Optional<RegisteredIncidentEntity> findTopByIpAndBlockedUntilAfterOrderByBlockedUntilDesc(
            String ip, LocalDateTime now
    );
    long countByIpAndIncidentTypeAndCreatedAtAfter(
            String ip, IncidentTypeEntity incidentType, LocalDateTime since
    );
}