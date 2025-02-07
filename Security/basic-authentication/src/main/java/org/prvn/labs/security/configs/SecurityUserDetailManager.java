package org.prvn.labs.security.configs;

import lombok.extern.slf4j.Slf4j;
import org.prvn.labs.security.model.User;
import org.prvn.labs.security.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;

@Slf4j
public class SecurityUserDetailManager implements UserDetailsManager {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    public SecurityUserDetailManager(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        log.info("SecurityUserDetailManager created --> {}, {}", userRepository.getClass().getSimpleName(), passwordEncoder.getClass().getSimpleName());
    }

    @Override
    public void createUser(UserDetails user) {
        var username = user.getUsername();
        var password = user.getPassword();
        User newUser = User.builder().username(username).password(passwordEncoder.encode(password)).build();
        userRepository.save(newUser);
    }

    @Override
    public void updateUser(UserDetails user) {

    }

    @Override
    public void deleteUser(String username) {
        userRepository.deleteUserByUsername(username);
    }

    @Override
    public void changePassword(String oldPassword, String newPassword) {

    }

    @Override
    public boolean userExists(String username) {
        return userRepository.findUserByUsername(username).isPresent();
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        var optionalUser = userRepository.findUserByUsername(username);
        var user = optionalUser.orElseThrow(() -> new UsernameNotFoundException(username));
        return new SecurityUserDetails(user);
    }
}
