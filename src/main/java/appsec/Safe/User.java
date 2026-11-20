package appsec.Safe;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class User {

    // TODO add constraints
    private String username;
    private String email;
    private String password;

}
