package com.example.colis.service;

import com.example.colis.entity.User;
import com.example.colis.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthService {

    private final UserRepository userRepository;

    @Value("${admin.email}")
    private String adminEmail;

    @Value("${admin.password}")
    private String adminPassword;

    public AuthService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public Optional<User> authenticate(String email, String password) {
        Optional<User> user = userRepository.findByEmail(email);

        if (user.isPresent() && user.get().getPassword().equals(password)) {
            return user;
        }
        return Optional.empty();
    }

    public boolean isAdmin(User user) {
        return user != null && adminEmail.equalsIgnoreCase(user.getEmail());
    }

    public User registerUser(User user, String passwordConfirm) {
        if (!user.getPassword().equals(passwordConfirm)) {
            throw new IllegalArgumentException("Les mots de passe ne correspondent pas");
        }

        if (userRepository.findByEmail(user.getEmail()).isPresent()) {
            throw new IllegalArgumentException("Cet email est déjà utilisé");
        }

        user.setEnabled(true);
        return userRepository.save(user);
    }
}