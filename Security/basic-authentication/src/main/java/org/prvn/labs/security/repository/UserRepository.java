package org.prvn.labs.security.repository;

import org.prvn.labs.security.model.User;
import org.springframework.context.annotation.Profile;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;
import java.util.UUID;

@Profile("userDefinedInDatabase")
public interface UserRepository extends CrudRepository<User, UUID> {
    Optional<User> getUserByUsername(String username);
}
