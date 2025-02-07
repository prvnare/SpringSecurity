package org.prvn.labs.security.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.context.annotation.Profile;

import java.util.UUID;

@Entity(name = "t_user")
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Data
@Profile("userDefinedInDatabase")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(columnDefinition = "varchar", unique = true, updatable = false, nullable = false)
    private UUID id;

    @Column(unique = true)
    private String username;

    @Column
    private String password;
}
