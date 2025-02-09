package org.prvn.labs.repository;

import org.prvn.labs.model.User;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends CrudRepository<User, UUID> {
    Optional<User> findUserByUsername(String username);

    void deleteUserByUsername(String username);
}
