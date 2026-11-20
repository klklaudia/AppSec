package appsec.Safe;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class Register {

    private final UserService userService;

    @PostMapping("/register")
    public String register(@ModelAttribute User user) {
        userService.createUser(user);
        return "Registered " + user.getUsername();
    }

}
