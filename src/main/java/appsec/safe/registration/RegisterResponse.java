package appsec.safe.registration;

import java.util.List;

public record RegisterResponse(String message, List<String> errors, String activationToken) {

}
