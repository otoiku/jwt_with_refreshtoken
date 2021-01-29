package com.github.otoiku.jwt_with_refreshtoken.repository;

import com.github.otoiku.jwt_with_refreshtoken.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, String> {
    Optional<User> findByUserId(String userId);
}
