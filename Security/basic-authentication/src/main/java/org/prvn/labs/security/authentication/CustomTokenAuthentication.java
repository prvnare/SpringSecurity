package org.prvn.labs.security.authentication;

import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class CustomTokenAuthentication extends OneTimeTokenAuthenticationToken {

    public CustomTokenAuthentication(Object principal, Collection<? extends GrantedAuthority> authorities) {
        super(principal, authorities);
    }
}
