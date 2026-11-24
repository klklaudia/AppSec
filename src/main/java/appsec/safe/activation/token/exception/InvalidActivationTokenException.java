package appsec.safe.activation.token.exception;

public class InvalidActivationTokenException extends RuntimeException {
    public InvalidActivationTokenException() {
        super("Invalid activation token.");
    }
}
