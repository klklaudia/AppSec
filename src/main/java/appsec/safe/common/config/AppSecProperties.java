package appsec.safe.common.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Security parameters from the draft documentation. Values live in application.properties;
 * the defaults below are only fallbacks and match the documented values.
 */
@Component
@ConfigurationProperties(prefix = "appsec")
@Getter
@Setter
public class AppSecProperties {

    /** Server-side secret mixed into password hashes (HMAC). Provide via APPSEC_PEPPER. */
    private String pepper;
    private Activation activation = new Activation();
    private RateLimit rateLimit = new RateLimit();

    @Getter
    @Setter
    public static class Activation {
        private String baseUrl = "http://localhost:8080/api/auth/activate";
        /** Token expires after 3 hours. */
        private long tokenTtlMinutes = 180;
        /** A new link can be requested at least 5 minutes after the previous one. */
        private long resendCooldownMinutes = 5;
        /** At most 3 activation links per user per day. */
        private int maxTokensPerUserPerDay = 3;
    }

    @Getter
    @Setter
    public static class RateLimit {
        /** 5 requests per 15 minutes per IP, then HTTP 429. */
        private int maxRequests = 5;
        private long windowMinutes = 15;
        /** Temporary block after exceeding the limit; repeated offences block the IP until an admin unblocks it. */
        private long blockMinutes = 15;
    }
}
