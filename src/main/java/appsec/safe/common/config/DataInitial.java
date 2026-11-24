package appsec.safe.common.config;

import appsec.safe.entity.IncidentTypeEntity;
import appsec.safe.repository.IncidentTypeRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
public class DataInitial implements CommandLineRunner {

    private final IncidentTypeRepository incidentTypeRepository;

    @Override
    public void run(String... args) {

        List.of(
                "SQLI_ATTEMPT",
                "XSS_ATTEMPT",
                "RATE_LIMIT_EXCEEDED",
                "INVALID_CAPTCHA"
        ).forEach(this::seedIncidentType);
    }

    private void seedIncidentType(String incidentName) {
        if (incidentTypeRepository.findByIncidentName(incidentName).isEmpty()) {
            incidentTypeRepository.save(IncidentTypeEntity.builder()
                    .incidentName(incidentName)
                    .build());
        }
    }
}