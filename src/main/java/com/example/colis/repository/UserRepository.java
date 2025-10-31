package com.example.colis.repository;

import com.example.colis.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);
    List<User> findByRole(String role);
    List<User> findTop5ByOrderByIdDesc();
    long countByRole(String role);
    @Query("SELECT u FROM User u ORDER BY u.createdAt DESC LIMIT 5")
    List<User> findTop5ByOrderByCreatedAtDesc();
    User findByEmailAndPassword(String email, String password);
}