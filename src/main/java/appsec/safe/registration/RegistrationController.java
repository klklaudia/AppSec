package appsec.safe.registration;

import appsec.safe.captcha.CaptchaService;
import appsec.safe.common.ApiResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping(path = "/api/auth", produces = MediaType.APPLICATION_JSON_VALUE)
@RequiredArgsConstructor
public class RegistrationController {

    private final RegistrationService registrationService;
    private final CaptchaService captchaService;

    /** JSON in, JSON out: user input is never reflected into an HTML response. */
    @PostMapping(path = "/register", consumes = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.CREATED)
    public ApiResponse register(@Valid @RequestBody RegisterRequest request, HttpServletRequest httpRequest) {
        // CAPTCHA is checked first, before any database lookup or password hashing.
        // getRemoteAddr() is used on purpose: X-Forwarded-For can be forged by the client.
        if (!captchaService.verify(request.captchaResponse(), httpRequest.getRemoteAddr())) {
            throw new RegistrationException(HttpStatus.BAD_REQUEST, "CAPTCHA verification failed. Please try again.");
        }
        registrationService.register(request);
        return new ApiResponse(
                "Account created.Check your e-mail to activate your account.",
                List.of());
    }
}
