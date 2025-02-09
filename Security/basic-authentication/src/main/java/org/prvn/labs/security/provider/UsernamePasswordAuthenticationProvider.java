package org.prvn.labs.security.provider;

import org.prvn.labs.security.authentication.UsernamePasswordAuthentication;
import org.prvn.labs.security.manager.SecurityUserDetailManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;


public class UsernamePasswordAuthenticationProvider implements AuthenticationProvider {

    // password encoder
    // userDetailService
    private final  PasswordEncoder passwordEncoder;
    private final SecurityUserDetailManager securityUserDetailManager;

    public UsernamePasswordAuthenticationProvider( PasswordEncoder passwordEncoder, SecurityUserDetailManager securityUserDetailManager ) {
        this.passwordEncoder = passwordEncoder;
        this.securityUserDetailManager = securityUserDetailManager;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        //logic to authenticate the authorization request
        String username = authentication.getPrincipal().toString();
        String password = authentication.getCredentials().toString();

        UserDetails userDetails = securityUserDetailManager.loadUserByUsername(username);
        if(passwordEncoder.matches(password, userDetails.getPassword())) {
            return new UsernamePasswordAuthenticationToken(username, password, userDetails.getAuthorities());
        }
        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {

        // what kind of authentication it supports
        return  authentication.equals(UsernamePasswordAuthentication.class);
    }
}
