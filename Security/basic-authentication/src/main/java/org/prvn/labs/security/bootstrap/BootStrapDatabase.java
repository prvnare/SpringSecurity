package org.prvn.labs.security.bootstrap;


import lombok.extern.slf4j.Slf4j;
import org.prvn.labs.security.model.User;
import org.prvn.labs.security.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import org.springframework.context.annotation.Profile;


@Slf4j
@Component
@Profile("userDefinedInDatabase")
public class BootStrapDatabase implements CommandLineRunner {

    private final UserRepository userRepository;

    public BootStrapDatabase(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public void run(String... args) throws Exception {

        if(userRepository.count() == 0) {
            log.info("No users found in database");
            userRepository.save(User.builder().username("admin").password("admin").build());
            userRepository.save(User.builder().username("bond").password("james").build());
        }
        log.info("userRepository.count() = " + userRepository.count());
    }
}









