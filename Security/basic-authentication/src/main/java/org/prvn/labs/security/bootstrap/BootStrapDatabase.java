package org.prvn.labs.security.bootstrap;


import lombok.extern.slf4j.Slf4j;
import org.prvn.labs.security.model.User;
import org.prvn.labs.security.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;


@Slf4j
@Component
@Profile("userDefinedInDatabase")
public class BootStrapDatabase implements CommandLineRunner {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    public BootStrapDatabase(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args)  {

        if(userRepository.count() == 0) {
            log.info("No users found in database");
            userRepository.save(User.builder().username("admin").password(passwordEncoder.encode("admin")).build());
            userRepository.save(User.builder().username("bond").password(passwordEncoder.encode("james")).build());
        }
        log.info("userRepository.count() = {}", userRepository.count());
    }
}









