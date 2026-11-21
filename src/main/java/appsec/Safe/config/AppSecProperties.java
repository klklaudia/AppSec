package appsec.Safe.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "appsec")
@Getter
@Setter
public class AppSecProperties {

    private String pepper;
    private Activation activation = new Activation();
    private RateLimit rateLimit = new RateLimit();

    @Getter
    @Setter
    public static class Activation {
        private String baseUrl = "http://localhost:8080/api/auth/activate";
        private long tokenTtlMinutes = 30;
        private int maxTokensPerUserPerHour = 5;
    }

    @Getter
    @Setter
    public static class RateLimit {
        private int maxRequests = 5;
        private long windowMinutes = 15;
        private long blockMinutes = 15;
    }
}