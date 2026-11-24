package appsec.safe.activation;

import appsec.safe.common.ApiResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class ActivationController {

    private final ActivationService activationService;

    @PostMapping("/activate")
    public ApiResponse activate(@Valid @RequestBody ActivationRequest request) {
        activationService.activate(request.token());
        return new ApiResponse("Your account was activated. Now you can log in.", List.of());
    }

    @PostMapping("/resend-activation")
    public ApiResponse resendLink(@RequestParam String email) {
        activationService.resendLink(email);
        return new ApiResponse("If this e-mail belongs to an account that is not activated yet, " +
                "we have sent a new link.", List.of());
    }
}
