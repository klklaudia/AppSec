package appsec.safe.captcha;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.time.Duration;
import java.util.Map;

/**
 * Server-side verification of Google reCAPTCHA v2 responses.
 * The widget in the browser can be bypassed, so only this check counts.
 */
@Slf4j
@Service
public class CaptchaService {

    private final RestClient restClient;
    private final String secretKey;
    private final String verifyUrl;

    public CaptchaService(@Value("${appsec.captcha.secret-key}") String secretKey,
                          @Value("${appsec.captcha.verify-url}") String verifyUrl) {
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(Duration.ofSeconds(5));
        requestFactory.setReadTimeout(Duration.ofSeconds(5));
        this.restClient = RestClient.builder().requestFactory(requestFactory).build();
        this.secretKey = secretKey;
        this.verifyUrl = verifyUrl;
    }

    /** Returns true only if Google confirms the response. Any error fails closed. */
    public boolean verify(String captchaResponse, String clientIp) {
        if (captchaResponse == null || captchaResponse.isBlank()) {
            return false;
        }

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("secret", secretKey);
        form.add("response", captchaResponse);
        if (clientIp != null) {
            form.add("remoteip", clientIp);
        }

        try {
            Map<?, ?> body = restClient.post()
                    .uri(verifyUrl)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve()
                    .body(Map.class);
            boolean success = body != null && Boolean.TRUE.equals(body.get("success"));
            if (!success) {
                log.warn("CAPTCHA rejected for ip={} errors={}", clientIp,
                        body == null ? null : body.get("error-codes"));
            }
            return success;
        } catch (RestClientException ex) {
            log.warn("CAPTCHA verification unavailable: {}", ex.getMessage());
            return false;
        }
    }
}
