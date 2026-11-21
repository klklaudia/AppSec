package appsec.safe.config;

import appsec.safe.entity.IncidentTypeEntity;
import appsec.safe.entity.RoleEntity;
import appsec.safe.repository.IncidentTypeRepository;
import appsec.safe.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
public class DataInitial implements CommandLineRunner {

    private final RoleRepository roleRepository;
    private final IncidentTypeRepository incidentTypeRepository;

    @Override
    public void run(String... args) {
        seedRole("USER", false);
        seedRole("ADMIN", true);

        List.of(
                "SQLI_ATTEMPT",
                "XSS_ATTEMPT",
                "RATE_LIMIT_EXCEEDED",
                "INVALID_CAPTCHA"
        ).forEach(this::seedIncidentType);
    }

    private void seedRole(String roleName, boolean canRemoveUsers) {
        if (roleRepository.findByRoleName(roleName).isEmpty()) {
            roleRepository.save(RoleEntity.builder()
                    .roleName(roleName)
                    .canRemoveUsers(canRemoveUsers)
                    .build());
        }
    }

    private void seedIncidentType(String incidentName) {
        if (incidentTypeRepository.findByIncidentName(incidentName).isEmpty()) {
            incidentTypeRepository.save(IncidentTypeEntity.builder()
                    .incidentName(incidentName)
                    .build());
        }
    }
}