package org.prvn.labs.security.authentication;

import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;

public class CustomTokenAuthentication extends OneTimeTokenAuthenticationToken {

    public CustomTokenAuthentication(String tokenValue) {
        super(null, tokenValue);
    }
}
