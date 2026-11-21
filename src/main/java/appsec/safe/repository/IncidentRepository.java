package appsec.safe.repository;

import appsec.safe.entity.IncidentTypeEntity;
import appsec.safe.entity.RegisteredIncidentEntity;
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