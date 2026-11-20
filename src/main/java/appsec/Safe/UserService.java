package appsec.Safe;

import org.springframework.stereotype.Service;

@Service
public class UserService {

    public void createUser(User user) {
        User newUser = new User(user.getUsername(), user.getEmail(), user.getPassword());
        //TODO repository
    }

}
