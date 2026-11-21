package appsec.safe.registration;

import appsec.safe.registration.RegistrationController.ApiResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.List;

/** Maps errors to a uniform JSON body without leaking stack traces or internals. */
@Slf4j
@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse> handleValidation(MethodArgumentNotValidException ex) {
        List<String> errors = ex.getBindingResult().getFieldErrors().stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .sorted()
                .toList();
        return body(HttpStatus.BAD_REQUEST, "Validation failed.", errors);
    }

    @ExceptionHandler(RegistrationException.class)
    public ResponseEntity<ApiResponse> handleRegistration(RegistrationException ex) {
        return body(ex.getStatus(), "Registration failed.", ex.getErrors());
    }

    @ExceptionHandler({HttpMessageNotReadableException.class, HttpMediaTypeNotSupportedException.class})
    public ResponseEntity<ApiResponse> handleBadRequest(Exception ex) {
        return body(HttpStatus.BAD_REQUEST, "Malformed request.", List.of());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse> handleUnexpected(Exception ex) {
        log.error("Unexpected error", ex);
        return body(HttpStatus.INTERNAL_SERVER_ERROR, "Unexpected server error.", List.of());
    }

    private static ResponseEntity<ApiResponse> body(HttpStatus status, String message, List<String> errors) {
        return ResponseEntity.status(status).body(new ApiResponse(message, errors));
    }
}
