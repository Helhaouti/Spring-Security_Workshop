package nl.hva.springsecuritydemo.config;

import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import lombok.RequiredArgsConstructor;
import nl.hva.springsecuritydemo.services.UserService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static nl.hva.springsecuritydemo.api.rest.AuthenticateController.AUTH_API_BASE;
import static nl.hva.springsecuritydemo.api.rest.UserController.USER_API_BASE;
import static nl.hva.springsecuritydemo.models.user.UserRole.ROLE_USER_NAME;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;


/**
 * The security configuration of the application.
 *
 * @author Hamza el Haouti
 */
@Configuration
@EnableWebSecurity

@RequiredArgsConstructor

@SecurityScheme(
        name = "Authorization",
        type = SecuritySchemeType.HTTP,
        bearerFormat = "JWT",
        in = SecuritySchemeIn.HEADER,
        scheme = "bearer"
)
public class SecurityConfig {

    private final PasswordEncoder passwordEncoder;
    private final UserService userService;
    private final JWTFilter tokenFilter;

    @Value("${spring.profiles.active}")
    private String activeProfile;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // No need for CSRF protection, given use of JWT with localstorage.
        http.csrf(AbstractHttpConfigurer::disable);
        // Disable default http basic login with a form.
        http.httpBasic(AbstractHttpConfigurer::disable).formLogin(AbstractHttpConfigurer::disable);

        // Enable cors protection for use with web browser.
        http.cors(Customizer.withDefaults());

        http.headers(headers -> {
            // Disable frame options to allow same-origin frames
            if (activeProfile.equals("dev"))
                headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin);
        });

        http.authorizeHttpRequests(request -> {
                    if (activeProfile.equals("dev"))
                        request.requestMatchers(
                                AntPathRequestMatcher.antMatcher("/h2-console/**"),
                                AntPathRequestMatcher.antMatcher("/swagger-ui/**"),
                                AntPathRequestMatcher.antMatcher("/v3/api-docs/**")
                        ).permitAll();

                    // Open endpoints
                    request.requestMatchers(
                            AntPathRequestMatcher.antMatcher(AUTH_API_BASE + "/**"),
                            AntPathRequestMatcher.antMatcher("/favicon.ico/")
                    ).permitAll();

                    // User role endpoints
                    request.requestMatchers(
                            AntPathRequestMatcher.antMatcher(USER_API_BASE + "/**")
                    ).hasRole(ROLE_USER_NAME);
                })
                // Set session management to stateless (for JWT)
                .sessionManagement(manager -> manager.sessionCreationPolicy(STATELESS));

        // Add JWT token filter
        http.addFilterBefore(tokenFilter, AuthorizationFilter.class);

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManagerBean() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();

        provider.setUserDetailsService(userService);
        provider.setPasswordEncoder(passwordEncoder);

        return new ProviderManager(provider);
    }

}