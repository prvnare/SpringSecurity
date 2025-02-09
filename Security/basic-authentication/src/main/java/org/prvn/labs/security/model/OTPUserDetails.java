package org.prvn.labs.security.model;

import org.prvn.labs.model.Otp;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

public class OTPUserDetails implements UserDetails {

    private final Otp otp;

    public OTPUserDetails(Otp otp) {
        this.otp = otp;
    }


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(()->"read");
    }

    @Override
    public String getPassword() {
        return otp.getOtp().toString();
    }

    @Override
    public String getUsername() {
        return otp.getUsername();
    }
}
