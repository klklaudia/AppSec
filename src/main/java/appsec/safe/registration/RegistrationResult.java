package appsec.safe.registration;

import appsec.safe.entity.UserEntity;

public record RegistrationResult(UserEntity user, String rawToken) {
}
