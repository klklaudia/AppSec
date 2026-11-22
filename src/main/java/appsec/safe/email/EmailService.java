package appsec.safe.email;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender mailSender;

    @Value("${appsec.mail.from}")
    private String from;

    @Value("${appsec.activation.base-url}")
    private String baseUrl;

    @Value("${appsec.activation.token-ttl-minutes}")
    private long ttlMinutes;

    public void sendActivationEmail(String to, String rawToken) {
        String link = baseUrl + "?token=" + rawToken;

        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(to);
        message.setSubject("Activate your account");
        message.setText(
                "Welcome!\n\n"
                        + "Click the link below to activate your account:\n"
                        + link + "\n\n"
                        + "The link is valid for " + ttlMinutes + " minutes.\n"
                        + "If you did not register, ignore this message.");

        mailSender.send(message);
    }
}