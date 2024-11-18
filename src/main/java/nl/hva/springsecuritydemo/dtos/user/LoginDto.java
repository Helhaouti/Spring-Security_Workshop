package nl.hva.springsecuritydemo.dtos.user;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import static nl.hva.springsecuritydemo.config.GenericConfig.PASSWORD_REGEX;


/**
 * DTO for user login data, encapsulating username and password.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginDto {

    @NotBlank(message = "Not provided.")
    String username;

    @NotBlank(message = "Not provided.")
    @Pattern(message = "Is invalid.", regexp = PASSWORD_REGEX)
    String password;

    public UsernamePasswordAuthenticationToken toAuthToken() {
        return new UsernamePasswordAuthenticationToken(this.getUsername(), this.getPassword());
    }

}
