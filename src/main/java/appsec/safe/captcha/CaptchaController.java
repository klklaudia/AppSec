package appsec.safe.captcha;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** Gives the browser the public site key, so it is configured in one place (not hard-coded in HTML). */
@RestController
public class CaptchaController {

    private final String siteKey;

    public CaptchaController(@Value("${appsec.captcha.site-key}") String siteKey) {
        this.siteKey = siteKey;
    }

    @GetMapping(path = "/api/captcha/site-key", produces = MediaType.APPLICATION_JSON_VALUE)
    public SiteKeyResponse siteKey() {
        return new SiteKeyResponse(siteKey);
    }

    public record SiteKeyResponse(String siteKey) {}
}
