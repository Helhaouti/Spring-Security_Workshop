package nl.hva.springsecuritydemo.config.beans;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;


@Configuration
public class DefaultPasswordEncoder {

    /**
     * Length of the random salt in bytes (for better uniqueness of hashes)
     */
    private static final int SALT_LENGTH = 16;
    /**
     * Length of the hash output in bytes
     */
    private static final int HASH_LENGTH = 32;
    /**
     * Number of parallel threads to use (1 for single-threaded hashing)
     */
    private static final int PARALLELISM = 1;

    /**
     * Memory cost parameter in kilobytes, affecting memory usage during hashing
     */
    private static final int MEMORY = 16384;

    /**
     * Number of iterations (time cost) to apply during hashing
     */
    private static final int ITERATIONS = 5;

    /**
     * Creates a password encoder.
     *
     * @return The created password encoder.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        // Creates and returns an Argon2 password encoder with the specified configuration
        return new Argon2PasswordEncoder(SALT_LENGTH, HASH_LENGTH, PARALLELISM, MEMORY, ITERATIONS);
    }

}
