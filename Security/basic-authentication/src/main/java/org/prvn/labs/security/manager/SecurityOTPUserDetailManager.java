package org.prvn.labs.security.manager;

import org.prvn.labs.model.Otp;
import org.prvn.labs.repository.OtpRepository;
import org.prvn.labs.security.model.OTPUserDetails;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.UserDetailsManager;

import java.util.Optional;
import java.util.UUID;

public class SecurityOTPUserDetailManager implements UserDetailsManager {

    private final OtpRepository otpRepository;

    public SecurityOTPUserDetailManager(OtpRepository otpRepository) {
        this.otpRepository = otpRepository;
    }

    @Override
    public void createUser(UserDetails userDetails) {
        String username = userDetails.getUsername();
        String password = userDetails.getPassword();
        Otp otp = Otp.builder().username(username)
                .otp(UUID.fromString(password))
                .build();
        otpRepository.save(otp);

    }

    @Override
    public void updateUser(UserDetails user) {

    }

    @Override
    public void deleteUser(String username) {

    }

    @Override
    public void changePassword(String oldPassword, String newPassword) {

    }

    @Override
    public boolean userExists(String username) {
        return otpRepository.findOtpByUsername(username).isPresent();
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<Otp> otpByUsername = otpRepository.findOtpByUsername(username);
        Otp otp = otpByUsername.orElseThrow(() -> new UsernameNotFoundException("Otp not found"));
        return  new OTPUserDetails(otp);
    }

}
