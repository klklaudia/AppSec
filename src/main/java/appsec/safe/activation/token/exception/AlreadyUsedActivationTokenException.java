package appsec.safe.activation.token.exception;

public class AlreadyUsedActivationTokenException extends RuntimeException {
    public AlreadyUsedActivationTokenException() {
        super("Activation token is no longer valid.");
    }
}
