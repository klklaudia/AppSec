package appsec.safe.repository;

import appsec.safe.entity.IncidentTypeEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface IncidentTypeRepository extends JpaRepository<IncidentTypeEntity, Integer> {
    Optional<IncidentTypeEntity> findByIncidentName(String incidentName);
}