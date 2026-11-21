package appsec.safe.registration;

import lombok.Getter;
import org.springframework.http.HttpStatus;

import java.util.List;

/** Business error raised during registration; carries the HTTP status and user-facing messages. */
@Getter
public class RegistrationException extends RuntimeException {

    private final HttpStatus status;
    private final List<String> errors;

    public RegistrationException(HttpStatus status, List<String> errors) {
        super(String.join("; ", errors));
        this.status = status;
        this.errors = List.copyOf(errors);
    }

    public RegistrationException(HttpStatus status, String error) {
        this(status, List.of(error));
    }
}
