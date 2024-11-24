package nl.hva.springsecuritydemo.api.rest;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import nl.hva.springsecuritydemo.dtos.user.LoginDto;
import nl.hva.springsecuritydemo.dtos.user.RegisterDto;
import nl.hva.springsecuritydemo.exceptions.BadRequest;
import nl.hva.springsecuritydemo.exceptions.UnauthorizedException;
import nl.hva.springsecuritydemo.models.user.User;
import nl.hva.springsecuritydemo.services.UserService;
import nl.hva.springsecuritydemo.utils.JWTUtil;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;


/**
 * The central place for the authentication of outside-users. Upon a successful login or registration it also
 * provides a JWToken, for future requests.
 */
@RestController
@RequestMapping(AuthenticateController.AUTH_API_BASE)

@RequiredArgsConstructor
public class AuthenticateController {

  public static final String AUTH_API_BASE = "/api/v1/auth";
  private final AuthenticationManager authManager;
  private final UserService userService;
  private final JWTUtil jwtUtil;

  /**
   * Checks whether the provided loginDto are valid, and authenticates the user, by returning a JWT.
   *
   * @param loginDto An object containing username and password attributes.
   * @return The user that belongs to the given loginDto and a JWT for use in authentication.
   */
  @PostMapping("/login")
  public ResponseEntity<Map<String, String>> login(@RequestBody @Valid LoginDto loginDto) {
    Authentication authenticate;

    try {
      authenticate = authManager.authenticate(loginDto.toAuthToken());
    } catch (BadCredentialsException ex) {
      throw new UnauthorizedException("Email and/or password is not valid.");
    } catch (DisabledException ex) {
      return new ResponseEntity<>(HttpStatus.FORBIDDEN);
    }

    var user = (User) authenticate.getPrincipal();

    return new ResponseEntity<>(
      jwtUtil.generateTokensFor(user),
      HttpStatus.ACCEPTED);
  }

  @PostMapping("/refresh")
  public ResponseEntity<Map<String, String>> refresh(
    @RequestBody
    @Valid @NotBlank(message = "refresh token not provided in body")
    String refreshToken
  ) {
    if (!jwtUtil.validate(refreshToken) || !jwtUtil.isRefreshToken(refreshToken))
      throw new BadRequest("The provided token is invalid");

    var user = userService.findById(jwtUtil.getUserIdOf(refreshToken));

    return new ResponseEntity<>(
      jwtUtil.generateTokensFor(user),
      HttpStatus.ACCEPTED
    );
  }

  /**
   * Creates a user with given parameters, when all parameters are provided and valid, in the provided object.
   *
   * @param req An object containing the attributes of the to be created User.
   * @return The created User object and a JWT token.
   */
  @PostMapping("/register")
  public ResponseEntity<Map<String, String>> register(@RequestBody @Valid RegisterDto req) {
    var user = userService.create(req);

    return new ResponseEntity<>(
      jwtUtil.generateTokensFor(user),
      HttpStatus.CREATED
    );
  }

}