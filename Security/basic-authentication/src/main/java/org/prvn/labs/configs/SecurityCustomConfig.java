package org.prvn.labs.configs;

import org.prvn.labs.repository.OtpRepository;
import org.prvn.labs.repository.UserRepository;
import org.prvn.labs.security.filter.CustomAuthenticationFilter;
import org.prvn.labs.security.filter.CustomTokenAuthenticationFilter;
import org.prvn.labs.security.manager.SecurityOTPUserDetailManager;
import org.prvn.labs.security.manager.SecurityUserDetailManager;
import org.prvn.labs.security.manager.TokenManager;
import org.prvn.labs.security.provider.TokenProvider;
import org.prvn.labs.security.provider.UsernameOTPAuthenticationProvider;
import org.prvn.labs.security.provider.UsernamePasswordAuthenticationProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.List;

@Configuration
@Profile("OtpAuthentication")
public class SecurityCustomConfig {

    private final OtpRepository otpRepository;
    private final UserRepository userRepository;

    public SecurityCustomConfig(UserRepository userRepository, OtpRepository otpRepository) {
        this.userRepository = userRepository;
        this.otpRepository = otpRepository;
    }

    // password encoder
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    // custom UserDetailManager to manage the users
    @Bean
    public SecurityUserDetailManager securityUserDetailManager() {
        return new SecurityUserDetailManager(userRepository, passwordEncoder())  ;
    }

    // Custom OTP UserDetailOTPManager
    @Bean
    public SecurityOTPUserDetailManager securityOTPUserDetailManager() {
       return  new SecurityOTPUserDetailManager(otpRepository);
    }


    @Bean
    public TokenManager tokenManager() {
        return new TokenManager();
    }

    @Bean
    public TokenProvider tokenProvider() {
        return new TokenProvider(tokenManager());
    }

    // custom provider to validate the otp
    @Bean
    public UsernameOTPAuthenticationProvider usernameOTPAuthenticationProvider() {
        return new UsernameOTPAuthenticationProvider(securityOTPUserDetailManager());
    }

    // custom provide to validate the username and password
    @Bean
    public UsernamePasswordAuthenticationProvider usernamePasswordAuthenticationProvider() {
        return new UsernamePasswordAuthenticationProvider(passwordEncoder(), securityUserDetailManager());
    }


    // authentication provider
    // add all the authentication provides to the Manager
    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(List.of(usernameOTPAuthenticationProvider(), usernamePasswordAuthenticationProvider(), tokenProvider()));
    }


    // registering customFilter in Filter chain
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .addFilterBefore(new CustomAuthenticationFilter(authenticationManager(), securityOTPUserDetailManager(), tokenManager()), UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(new CustomTokenAuthenticationFilter(authenticationManager()), CustomAuthenticationFilter.class)
                .build();
    }

}
