package org.prvn.labs.repository;

import org.prvn.labs.model.Otp;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;



public interface OtpRepository  extends JpaRepository<Otp, Integer> {
    Optional<Otp> findOtpByUsername(String username);
}
