package org.prvn.labs.security.provider;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

@Slf4j
public class CustomSecurityAuthenticationProvider implements AuthenticationProvider {

    private final PasswordEncoder passwordEncoder;
    private final UserDetailsService userDetailsService;

    public CustomSecurityAuthenticationProvider(PasswordEncoder passwordEncoder, UserDetailsService userDetailsService) {
        this.passwordEncoder = passwordEncoder;
        this.userDetailsService = userDetailsService;
    }
    /*
         * provide logic to verify the authentication of the given user somehow
         * if found return Authentication
         * found but not a valid User then throw the Authentication Exception
         * if Authentication is not then return null , Authentication Manager will handel the null and checks other Authentication Providers to validate the user

    */

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String username = authentication.getName();
        String password = authentication.getCredentials().toString();
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        if(passwordEncoder.matches(password, userDetails.getPassword())) {
            return new UsernamePasswordAuthenticationToken(username, password, userDetails.getAuthorities());
        }
        return null;
    }

    /*
           supports is used to tell the authentication manager
           that this authentication provider supports which kind of Authentication Requests.

           There can be a scenarios where supports says I do authenticate these authentication requests
           but your authentication() logic is not capable of handling those authentication Requests
     */

    @Override
    public boolean supports(Class<?> authenticationType) {
        log.debug("supports authentication type {}", authenticationType);
        return UsernamePasswordAuthenticationToken.class.equals(authenticationType);
    }

}
