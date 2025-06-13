package com.pennywise.authService.configs;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class SecurityConfig {

    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf().disable() // Disable CSRF if you're building a stateless API
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/signup", "/auth/login", "/auth/verify").permitAll() // public endpoints
                        .anyRequest().authenticated() // everything else needs authentication
                );

        return http.build();
    }

    @Bean
    public Argon2PasswordEncoder encoder(){
        //TODO: look at different tuning param values
        log.info("using custom encoder fosho");
        return new Argon2PasswordEncoder(
                16, // salt length in bytes
                32, // hash length in bytes
                4,  // parallelism
                1 << 16, // memory cost (65536 KB = 64MB)
                5   // iterations
        );
    }

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                        .allowedOrigins("http://localhost:3000") // or your frontend domain
                        .allowedMethods("*")
                        .allowCredentials(true); // <- THIS IS CRUCIAL
            }
        };
    }
}
