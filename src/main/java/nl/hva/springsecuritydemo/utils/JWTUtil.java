package nl.hva.springsecuritydemo.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import nl.hva.springsecuritydemo.models.user.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;


/**
 * A utility to perform operations relating to JWT tokens.
 */
@Component
@RequiredArgsConstructor
public class JWTUtil {

  public static final long JWT_ACCESS_DURATION_MS = 1000L * 60 * 60 * 2;  // 2 hours
  public static final long JWT_REFRESH_DURATION_MS = 1000L * 60 * 60 * 24 * 30 * 6;  // 6 months on average

  public static final String JWT_TOKEN_PREFACE = "Bearer ";

  public static final String JWT_CLAIM_KEY_USER_ID = "user-id";
  public static final String JWT_CLAIM_KEY_USER_ROLES = "user-roles";
  public static final String JWT_CLAIM_KEY_TOKEN_TYPE = "token-type";
  public static final String JWT_CLAIM_KEY_TOKEN_TYPE_REFRESH = "refresh";

  private static final Logger log = LoggerFactory.getLogger(JWTUtil.class);

  private final SecretKey signingKey;

  @Value("${jwt.issuer:MyOrganisation}")
  private String issuer;

  /**
   * Parses the body of a JWT in string format, with the provided key, to a JWS object.
   *
   * @param token A JWT in string format.
   * @param key   Key used to decode the JWT.
   * @return The body of the JWT in a JWS object.
   */
  private static Jws<Claims> parseToken(String token, SecretKey key) {
    return Jwts.parser()
      .verifyWith(key)
      .build()
      .parseSignedClaims(token);
  }

  public Map<String, String> generateTokensFor(User user) {
    return Map.of(
      "accessToken", generateAccessTokenFor(user),
      "refreshToken", generateRefreshTokenFor(user)
    );
  }

  @SneakyThrows
  private String generateAccessTokenFor(User user) {
    return Jwts.builder()
      .claim(JWT_CLAIM_KEY_USER_ID, user.getId())
      .claim(JWT_CLAIM_KEY_USER_ROLES, user.getAuthorities())

      .issuer(issuer)
      .issuedAt(new Date())
      .expiration(new Date(System.currentTimeMillis() + JWT_ACCESS_DURATION_MS))

      .signWith(signingKey)
      .compact();
  }

  @SneakyThrows
  private String generateRefreshTokenFor(User user) {
    return Jwts.builder()
      .claim(JWT_CLAIM_KEY_USER_ID, user.getId())
      .claim(JWT_CLAIM_KEY_USER_ROLES, user.getAuthorities())
      .claim(JWT_CLAIM_KEY_TOKEN_TYPE, JWT_CLAIM_KEY_TOKEN_TYPE_REFRESH)

      .issuer(issuer)
      .issuedAt(new Date())
      .expiration(new Date(System.currentTimeMillis() + JWT_REFRESH_DURATION_MS))

      .signWith(signingKey)
      .compact();
  }

  /**
   * Checks whether the provided jwt token is valid.
   *
   * @param token The token to be validated.
   * @return Whether the token is valid.
   */
  public boolean validate(String token) {
    try {
      parseToken(token, signingKey);

      return true;
    } catch (SignatureException e) {
      log.error("Invalid JWT signature - {}", e.getMessage());
    } catch (MalformedJwtException e) {
      log.error("Invalid JWT token - {}", e.getMessage());
    } catch (ExpiredJwtException e) {
      log.error("Expired JWT token - {}", e.getMessage());
    } catch (UnsupportedJwtException e) {
      log.error("Unsupported JWT token - {}", e.getMessage());
    } catch (IllegalArgumentException e) {
      log.error("JWT claims string is empty - {}", e.getMessage());
    }

    return false;
  }

  /**
   * Extracts the user object from the payload of the JWToken.
   *
   * @param token The token containing the username.
   * @return the user object of the authenticated user.
   */
  public UUID getUserIdOf(String token) {
    var uuidString = (String) parseToken(token, signingKey)
      .getPayload()
      .get(JWT_CLAIM_KEY_USER_ID);

    return UUID.fromString(uuidString);
  }

  public boolean isRefreshToken(String token) {
    return Objects
      .requireNonNullElse(
        parseToken(token, signingKey)
          .getPayload()
          .get(JWT_CLAIM_KEY_TOKEN_TYPE),
        ""
      ).equals(JWT_CLAIM_KEY_TOKEN_TYPE_REFRESH);
  }

}