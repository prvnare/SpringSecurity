package org.prvn.labs.security.configs;

import lombok.extern.slf4j.Slf4j;
import org.prvn.labs.security.model.User;
import org.prvn.labs.security.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Optional;

@Slf4j
public class SecurityUserDetailService implements UserDetailsService {

    private final UserRepository userRepository;

    public SecurityUserDetailService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info("Loading user ----->  {}", username);
       Optional<User> optionalUser =  userRepository.getUserByUsername(username);
        User user = optionalUser.orElseThrow(() -> new UsernameNotFoundException(username));
        return new SecurityUserDetails(user);
    }
}
