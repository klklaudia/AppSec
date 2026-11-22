package appsec.safe.activation;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ActivationRequest(
        @NotBlank @Size(max = 200) String token
) {}