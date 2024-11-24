package nl.hva.springsecuritydemo.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import nl.hva.springsecuritydemo.exceptions.ConflictException;
import nl.hva.springsecuritydemo.models.user.User;
import nl.hva.springsecuritydemo.services.UserService;
import nl.hva.springsecuritydemo.utils.JWTUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Objects;

import static nl.hva.springsecuritydemo.utils.JWTUtil.JWT_TOKEN_PREFACE;
import static org.springframework.util.StringUtils.hasLength;


/**
 * A filter to capture JWT tokens embedded in HTTP Authorizations header from incoming requests.
 * If a JWT is present it validates it and authenticates the user.
 */
@Component
@RequiredArgsConstructor
public class JWTFilter extends OncePerRequestFilter {

  private static final Logger logger = LoggerFactory.getLogger(JWTFilter.class);
  private final UserService userService;
  private final JWTUtil jwtUtil;

  @Override
  protected void doFilterInternal(
    HttpServletRequest req,
    HttpServletResponse res,
    FilterChain chain
  ) throws ServletException, IOException {
    var authHeader = req.getHeader(HttpHeaders.AUTHORIZATION);

    logger.info("Processing request to URI: {}", req.getRequestURI());

    // Check if a JWT is not present in the header, and pass to the next filter.
    if (!hasLength(authHeader) || !authHeader.startsWith(JWT_TOKEN_PREFACE)) {
      logger.debug("No valid Authorization header found. Skipping JWT validation.");
      chain.doFilter(req, res);
      return;
    }

    var token = authHeader.replace(JWT_TOKEN_PREFACE, "").trim();
    logger.debug("Extracted token: {}", token);

    // Check if the provided JWT token is invalid, and pass to the next filter.
    if (!jwtUtil.validate(token)) {
      logger.warn("JWT token validation failed.");
      chain.doFilter(req, res);
      return;
    }

    // Extract user ID from the token.
    var userId = jwtUtil.getUserIdOf(token);
    logger.debug("Extracted user ID from token: {}", userId);

    User user = userService.findById(userId);

    if (user == null) {
      logger.warn("No user found for ID: {}. Skipping authentication.", userId);
      chain.doFilter(req, res);
      return;
    }

    if (!user.isEnabled()) {
      logger.error("User account with ID: {} is disabled.", userId);
      throw new ConflictException("Your account is disabled. Check your email for the activation link.");
    }

    logger.info("User ID: {} authenticated successfully. Setting up security context.", userId);

    var authToken = new UsernamePasswordAuthenticationToken(
      user,
      null,
      Objects.requireNonNullElse(user.getAuthorities(), List.of())
    );

    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(req));
    SecurityContextHolder.getContext().setAuthentication(authToken);

    logger.debug("Security context set for user ID: {}", userId);
    chain.doFilter(req, res);
  }

}
