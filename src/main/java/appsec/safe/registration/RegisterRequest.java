package appsec.safe.registration;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Past;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.time.LocalDate;

/**
 * Registration form data. Constraints mirror the table in the draft documentation;
 * the client-side checks in register.html are only a convenience, these are authoritative.
 */
public record RegisterRequest(

        @NotBlank(message = "Username is required.")
        @Pattern(regexp = "^[A-Za-z0-9]{3,20}$",
                message = "Username must be 3-20 characters, letters and digits only.")
        String username,

        @NotBlank(message = "E-mail is required.")
        @Email(message = "E-mail address is not valid.")
        @Size(max = 254, message = "E-mail address is too long.")
        String email,

        // Detailed password rules (upper/lower/digit, no username/e-mail) are checked by PasswordManager.
        @NotBlank(message = "Password is required.")
        @Size(min = 8, max = 30, message = "Password must be 8-30 characters.")
        String password,

        // Response token from the reCAPTCHA widget (g-recaptcha-response), verified with Google on the server.
        @NotBlank(message = "Please confirm that you are not a robot.")
        @Size(max = 4000, message = "CAPTCHA response is too long.")
        String captchaResponse
) {
    @Override
    public String toString() {
        // Never let the password end up in logs.
        return "RegisterRequest[username=" + username + ", email=" + email + "]";
    }
}
