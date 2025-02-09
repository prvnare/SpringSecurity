package org.prvn.labs.security.service;

import lombok.extern.slf4j.Slf4j;
import org.prvn.labs.security.model.SecurityUserDetails;
import org.prvn.labs.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

@Slf4j
public class SecurityUserDetailService implements UserDetailsService {

    private final UserRepository userRepository;

    public SecurityUserDetailService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info("Loading user ----->  {}", username);
        var optionalUser =  userRepository.findUserByUsername(username);
        var user = optionalUser.orElseThrow(() -> new UsernameNotFoundException(username));
        return new SecurityUserDetails(user);
    }
}
