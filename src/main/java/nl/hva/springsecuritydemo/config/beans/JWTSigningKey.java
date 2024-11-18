package nl.hva.springsecuritydemo.config.beans;

import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


@Configuration
public class JWTSigningKey {

    @Value("${jwt.signing-secret}")
    private String passPhrase;

    /**
     * Generates a key based on secret and unique string.
     *
     * @return A key that can be used to en-/decrypt a JWT
     */
    @Bean
    public SecretKey getKey() {
        byte[] hmacKey = passPhrase.getBytes(StandardCharsets.UTF_16);
        return Keys.hmacShaKeyFor(hmacKey);
    }

}
