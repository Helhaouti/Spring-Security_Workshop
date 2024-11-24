package nl.hva.springsecuritydemo.dtos.user;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

import static nl.hva.springsecuritydemo.config.GenericConfig.EMAIL_REGEX;
import static nl.hva.springsecuritydemo.config.GenericConfig.PASSWORD_REGEX;


/**
 * DTO for editing an existing user.
 */
@Data
public class UpdateDto {

  @Email(regexp = EMAIL_REGEX, message = "Is invalid.")
  private String email;
  @Pattern(regexp = PASSWORD_REGEX, message = "Is invalid.")
  private String password;
  private String username;

}
