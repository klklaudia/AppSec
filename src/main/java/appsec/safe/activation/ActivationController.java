package appsec.safe.activation;

import appsec.safe.registration.ApiResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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
}
