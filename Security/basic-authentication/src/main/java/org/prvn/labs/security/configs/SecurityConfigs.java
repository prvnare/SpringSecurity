package org.prvn.labs.security.configs;

import org.prvn.labs.security.repository.UserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;

import javax.sql.DataSource;

@Configuration
public class SecurityConfigs  {

    @Bean
    @Profile({"userDefinedInMemory","customAuthenticationProvider"})
    public UserDetailsService userDetailsService() {
        return new InMemoryUserDetailsManager(
                new User("user", "password", AuthorityUtils.createAuthorityList("ROLE_USER")),
                new User("admin", "password", AuthorityUtils.createAuthorityList("ROLE_ADMIN")),
                new User("bob", "password", AuthorityUtils.createAuthorityList("ROLE_ADMIN", "ROLE_USER"))
        );
    }

    /*
            Using custom Authentication Provider where it uses User Detail service
            and Password Encoder to authenticate the user
            UserDetailService is InMemoryUserDetailService
            PasswordEncoder is NoOpPasswordEncoder

            --> It's not mandatory  to always use same kind of UserDetailsService and PasswordEncoder
            in the Authentication Provider. Somehow your Authentication Provider should be in capable of validating the
            Authentication Request delegated to your custom authentication provider

            --> Now, SpringSecurity is  capable of understanding your custom authentication provider so
            it register this custom authentication provider with authentication manager and it adds to collection of
            authentication provider

     */

    @Bean
    @Profile("customAuthenticationProvider")
    public AuthenticationProvider authenticationProvider(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        return new CustomSecurityAuthenticationProvider(passwordEncoder, userDetailsService);
    }


    @Bean
    @Profile({"userDefinedInMemory","customAuthenticationProvider"})
    public PasswordEncoder passwordEncoder() {
        return  NoOpPasswordEncoder.getInstance();
    }


    @Bean
    @Profile("userDefinedInDatabase")
    public UserDetailsService getCustomUserDetailManager(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        // Using custom UserDetailManager which internally extends the UserDetailService
        return new SecurityUserDetailManager(userRepository, passwordEncoder);
    }


    @Bean
    @Profile("userDefinedInDatabase")
    public PasswordEncoder getPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }



    /* Using predefined JDBC connected User details service rather than using our own.
         the only thing is, need to follow the same table structure as spring security is expecting
         Tables like users and authorities should be created accordingly. you can check other tables in the code.
     */
    public UserDetailsService userDetailsService(DataSource dataSource) {
        return new JdbcUserDetailsManager( dataSource);
    }


    // using custom UserDetailService
    public UserDetailsService userDetailsServiceDatabase(UserRepository userRepository) {
        return new SecurityUserDetailService(userRepository);
    }


}
