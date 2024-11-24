package nl.hva.springsecuritydemo.api.rest;

import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import nl.hva.springsecuritydemo.dtos.user.UpdateDto;
import nl.hva.springsecuritydemo.models.user.User;
import nl.hva.springsecuritydemo.services.UserService;
import nl.hva.springsecuritydemo.utils.JWTUtil;
import nl.hva.springsecuritydemo.utils.SecurityContextUtil;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.UUID;

import static nl.hva.springsecuritydemo.api.rest.UserController.USER_API_BASE;


/**
 * Controller class for handling user-related operations.
 * Provides endpoints for various user management tasks like retrieving user details, updating user information, and deleting a user.
 */
@RestController
@RequestMapping(USER_API_BASE)

@Valid

@RequiredArgsConstructor

@SecurityRequirement(name = "Authorization")

public class UserController {

  public final static String USER_API_BASE = "/api/v1/user";

  private final UserService userService;
  private final JWTUtil jwtUtil;

  /**
   * Easy method to return current user.
   *
   * @return current user
   */
  @GetMapping
  public User getUser() {
    return SecurityContextUtil.getUser();
  }

  /**
   * Finds a user by their unique id.
   *
   * @param id The UUID of the user to find.
   * @return The found user, or null if not found.
   */
  @GetMapping("/{id}")
  public User findById(@PathVariable UUID id) {
    return userService.findById(id);
  }

  /**
   * Finds a user by their email address.
   *
   * @param email The email address of the user to find.
   * @return The found user, or null if not found.
   */
  @GetMapping("/email/{email}")
  public User findByEmail(@PathVariable @NotBlank(message = "is blank.") String email) {
    return userService.findByEmail(email);
  }

  /**
   * Finds a user by their username.
   *
   * @param username The username of the user to find.
   * @return The found user, or null if not found.
   */
  @GetMapping("/username/{username}")
  public User findByUsername(@PathVariable() @NotBlank(message = "is blank.") String username) {
    return userService.findByUserName(username);
  }

  /**
   * Updates the parameters of the current user.
   *
   * @param updateDto the potential new parameters of the user (any are optional).
   * @return The updated user.
   */
  @Valid
  @SneakyThrows
  @PutMapping
  public ResponseEntity<Map<String, String>> updateUserParam(@RequestBody UpdateDto updateDto) {
    var updatedUser = userService.update(updateDto);

    return new ResponseEntity<>(
      jwtUtil.generateTokensFor(updatedUser),
      HttpStatus.ACCEPTED
    );
  }

  /**
   * Deletes the current user.
   */
  @PostMapping("/delete")
  public void deleteUser() {
    userService.remove(SecurityContextUtil.getUser());
  }

}
