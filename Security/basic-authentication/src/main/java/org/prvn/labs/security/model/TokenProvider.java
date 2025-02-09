package org.prvn.labs.security.model;

import org.prvn.labs.security.authentication.CustomTokenAuthentication;
import org.prvn.labs.security.manager.TokenManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.util.UUID;

public class TokenProvider implements AuthenticationProvider {

    private final TokenManager tokenManager;

    public TokenProvider(TokenManager tokenManager) {
        this.tokenManager = tokenManager;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        var flag =  tokenManager.contains(UUID.fromString((String) authentication.getPrincipal()));
        if(flag){
            authentication.setAuthenticated(true);
            return authentication;
        }else {
            throw new BadCredentialsException("Bad credentials");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(CustomTokenAuthentication.class);
    }
}
