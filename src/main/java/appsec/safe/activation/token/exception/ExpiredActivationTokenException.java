package appsec.safe.activation.token.exception;

public class ExpiredActivationTokenException extends RuntimeException {
    public ExpiredActivationTokenException() {
        super("Activation token has expired.");
    }
}