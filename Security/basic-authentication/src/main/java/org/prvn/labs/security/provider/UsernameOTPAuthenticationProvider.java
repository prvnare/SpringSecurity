package org.prvn.labs.security.provider;

import org.prvn.labs.security.authentication.UsernameOTPAuthentication;
import org.prvn.labs.security.manager.SecurityOTPUserDetailManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;


public class UsernameOTPAuthenticationProvider implements AuthenticationProvider {


    // UserDetailService
    private final SecurityOTPUserDetailManager securityOTPUserDetailManager;

    public UsernameOTPAuthenticationProvider(SecurityOTPUserDetailManager securityOTPUserDetailManager) {
        this.securityOTPUserDetailManager = securityOTPUserDetailManager;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        // logic to how to authenticate the authentication request
        String user = authentication.getPrincipal().toString();
        String password = authentication.getCredentials().toString();

        UserDetails userDetails = securityOTPUserDetailManager.loadUserByUsername(user);
        if(userDetails.getPassword().equals(password)){
            return new UsernamePasswordAuthenticationToken(user, password, userDetails.getAuthorities());
        }
       return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        // logic to support which kind of authentication requests
        return authentication.equals(UsernameOTPAuthentication.class);
    }

}
