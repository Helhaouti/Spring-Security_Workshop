package nl.hva.springsecuritydemo.dtos.user;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.EqualsAndHashCode;
import nl.hva.springsecuritydemo.models.user.User;
import org.springframework.security.crypto.password.PasswordEncoder;

import static nl.hva.springsecuritydemo.config.GenericConfig.EMAIL_REGEX;


/**
 * DTO for registering a new user, extending from LoginDto and including an email field.
 */
@Data
@EqualsAndHashCode(callSuper = true)
public class RegisterDto extends LoginDto {

    @NotBlank(message = "Not provided.")
    @Email(message = "Is invalid.", regexp = EMAIL_REGEX)
    private String email;

    public RegisterDto(String username, String password, String email) {
        super(username, password);
        this.email = email;
    }

    public User toUser(PasswordEncoder encoder) {
        return User.builder()
                .email(getEmail())
                .password(encoder.encode(getPassword()))
                .username(getUsername())
                .build();
    }

}
