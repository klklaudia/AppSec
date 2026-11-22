package appsec.safe.registration;

import appsec.safe.captcha.CaptchaService;
import appsec.safe.email.EmailService;
import appsec.safe.entity.UserEntity;
import appsec.safe.repository.TokenRepository;
import appsec.safe.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class RegistrationControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @BeforeEach
    void cleanDatabase() {
        userRepository.deleteAll();
    }

    private static String json(String username, String email, String password) {
        return """
                {"username":"%s","email":"%s","password":"%s","name":null,"surname":null,"birthday":null}
                """.formatted(username, email, password);
    }

    private org.springframework.test.web.servlet.ResultActions register(String body) throws Exception {
        return mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON, MediaType.TEXT_HTML)
                .content(body));
    }

    @Test
    void validRegistrationCreatesInactiveUserWithHashedPassword() throws Exception {
        register(json("alice1", "Alice@Example.com", "Secret123"))
                .andExpect(status().isCreated())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON));

        UserEntity user = userRepository.findByUsername("alice1").orElseThrow();
        assertFalse(user.isActive());
        assertTrue(user.getHashedPassword().startsWith("$argon2id$"));
        assertTrue(user.getEmail().equals("alice@example.com"));
    }

    @Test
    void invalidInputIsRejectedByServerSideValidation() throws Exception {
        register(json("<script>", "not-an-email", "short"))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.errors", hasItem(containsString("username"))))
                .andExpect(jsonPath("$.errors", hasItem(containsString("email"))))
                .andExpect(jsonPath("$.errors", hasItem(containsString("password"))));
    }

    @Test
    void weakPasswordIsRejected() throws Exception {
        register(json("bob123", "bob@example.com", "bob123bob"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void duplicateInactiveAccountIsReported() throws Exception {
        register(json("carol1", "carol@example.com", "Secret123")).andExpect(status().isCreated());

        register(json("carol1", "carol@example.com", "Secret123"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.errors[0]", containsString("not been activated")));
    }

    @Test
    void takenUsernameAndEmailAreRejected() throws Exception {
        register(json("dave1", "dave@example.com", "Secret123")).andExpect(status().isCreated());

        register(json("dave1", "other@example.com", "Secret123")).andExpect(status().isConflict());
        register(json("dave2", "dave@example.com", "Secret123")).andExpect(status().isConflict());
    }

    @Test
    void malformedJsonGivesBadRequest() throws Exception {
        register("{not json").andExpect(status().isBadRequest());
    }
}
