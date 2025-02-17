package org.prvn.labs.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

@Configuration
//@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true, proxyTargetClass = true)
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, HandlerMappingIntrospector introspector) throws Exception {
        // Disables the authentication
        return http
                .httpBasic(Customizer.withDefaults())
               // .securityMatchers(request -> request.requestMatchers("/dummy"))   --> specifying which endpoint to go through with the filters
               // .securityMatchers(requestMatcherConfigurer -> requestMatcherConfigurer.requestMatchers("/hello"))
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers(new MvcRequestMatcher(introspector, "/hello")).authenticated();
                    auth.requestMatchers(new MvcRequestMatcher(introspector, "/dummy")).hasRole("ADMIN" );
                    auth.requestMatchers(new MvcRequestMatcher(introspector, "/special")).permitAll();

                    // auth.requestMatchers(new RegexRequestMatcher("[??]","")).authenticated();

                    // authorizeRequests.requestMatchers("/dummy").authenticated();
                    // authorizeRequests.anyRequest().authenticated();
                    // auth.requestMatchers(HttpMethod.GET, "/special").permitAll();
                    // auth.requestMatchers(matcher-> matcher.getRequestURI().equals("/special") && matcher.getMethod() == HttpMethod.GET.name()).permitAll();
                    // using MVCRequestMatcher
                    // authorizeRequests.requestMatchers(new MvcRequestMatcher(introspector,"/hello")).authenticated();
                    // authorizeRequests.requestMatchers("/hello").authenticated(); --> httpBasic is required to authenticate the user
                    // authorizeRequests.anyRequest().permitAll(); --> httpBasic is not requires
                    // authorizeRequests.anyRequest().hasRole("USER"); --> allows who is having the USER role  --> Basic always required if you do any authentication

                })
                .build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        var userDetailsService = new InMemoryUserDetailsManager();
        var userDetails = User.withUsername("user").password(passwordEncoder().encode("password")).roles("USER").build();
        var adminUserDetails = User.withUsername("admin").password(passwordEncoder().encode("password")).roles("ADMIN").build();
        userDetailsService.createUser(userDetails);
        userDetailsService.createUser(adminUserDetails);
        return userDetailsService;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}