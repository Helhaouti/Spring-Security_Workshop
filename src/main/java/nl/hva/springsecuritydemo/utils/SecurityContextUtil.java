package nl.hva.springsecuritydemo.utils;

import java.util.Objects;
import nl.hva.springsecuritydemo.models.user.User;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;


public class SecurityContextUtil {

    public static Authentication getAuth() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    public static User getUser() {
        return getUser(true);
    }

    public static User getUser(boolean nullable) {
        var currUser = getAuth() == null ? null : (User) getAuth().getPrincipal();

        return nullable ? currUser : Objects.requireNonNull(currUser);
    }

    private SecurityContextUtil() {
    }

}
