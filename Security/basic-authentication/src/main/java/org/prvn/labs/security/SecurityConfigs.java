package org.prvn.labs.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class SecurityConfigs {

    @Bean
    public UserDetailsService userDetailsService() {
        return new InMemoryUserDetailsManager(
                new User("user", "password", AuthorityUtils.createAuthorityList("ROLE_USER")),
                new User("admin", "password", AuthorityUtils.createAuthorityList("ROLE_ADMIN")),
                new User("bob", "password", AuthorityUtils.createAuthorityList("ROLE_ADMIN", "ROLE_USER"))
        );
    }


    @Bean
    public PasswordEncoder passwordEncoder() {
        return  NoOpPasswordEncoder.getInstance();
    }
}
