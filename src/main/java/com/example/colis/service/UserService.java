package com.example.colis.service;

import com.example.colis.entity.User;
import com.example.colis.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class UserService {

    private final UserRepository userRepository;

    @Value("${admin.email}")
    private String adminEmail;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public boolean isAdmin(User user) {
        return user != null && "ADMIN".equalsIgnoreCase(user.getRole());
    }

    public User createUser(User user) {
        return userRepository.save(user);
    }

    public User updateUser(User user) {
        return userRepository.save(user);
    }

    public void deleteUser(Long id) {
        userRepository.deleteById(id);
    }

    public Optional<User> findById(Long id) {
        return userRepository.findById(id);
    }

    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public List<User> findAllUsers() {
        return userRepository.findAll();
    }

    public List<User> findRecentUsers(int limit) {
        return userRepository.findTop5ByOrderByCreatedAtDesc();
    }

    public List<User> findByRole(String role) {
        return userRepository.findByRole(role);
    }

    public long countUsersByRole(String role) {
        return userRepository.countByRole(role);
    }

    public User approveLivreur(Long livreurId) {
        User livreur = userRepository.findById(livreurId)
                .orElseThrow(() -> new IllegalArgumentException("Livreur non trouvé"));
        livreur.setLivreurApproved(true);
        return userRepository.save(livreur);
    }


}