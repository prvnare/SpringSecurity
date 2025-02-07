package org.prvn.labs.security.configs;

import org.prvn.labs.security.repository.UserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
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
public class SecurityConfigs {

    @Bean
    @Profile("userDefinedInMemory")
    public UserDetailsService userDetailsService() {
        return new InMemoryUserDetailsManager(
                new User("user", "password", AuthorityUtils.createAuthorityList("ROLE_USER")),
                new User("admin", "password", AuthorityUtils.createAuthorityList("ROLE_ADMIN")),
                new User("bob", "password", AuthorityUtils.createAuthorityList("ROLE_ADMIN", "ROLE_USER"))
        );
    }

    @Bean
    @Profile({"userDefinedInMemory",})
    public PasswordEncoder passwordEncoder() {
        return  NoOpPasswordEncoder.getInstance();
    }

    @Bean
    @Profile("userDefinedInDatabase")

    public UserDetailsService userDetailsServiceDatabase(UserRepository userRepository, PasswordEncoder passwordEncoder) {
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
