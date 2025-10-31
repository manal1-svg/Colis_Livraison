package com.example.colis.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Table(name = "users")
@Getter @Setter
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String fullName;

    @Column(nullable = false)
    private String role; // ADMIN, USER, LIVREUR

    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column(name = "is_approved")
    private boolean isApproved = true;

    @Getter
    @Setter
    @Column(name = "livreur_approved", columnDefinition = "boolean default false")
    private boolean livreurApproved;


    private String vehiculeType;
    private String licensePlate;
    private String phoneNumber;



    @Column(nullable = false)
    private boolean enabled;
    private boolean enMission;

    // Getters et Setters
    public boolean isApproved() {
        return isApproved;
    }

    public void setApproved(boolean approved) {
        isApproved = approved;
    }

    private boolean accountNonExpired = true;
    private boolean accountNonLocked = true;
    private boolean credentialsNonExpired = true;


    public boolean isEnMission() {
        // Vérifie d'abord si l'utilisateur est un livreur
        if (!this.getRole().equals("LIVREUR")) {
            return false;
        }

        // Vérifie si le livreur est approuvé/actif
        if (!this.isApproved()) {
            return false;
        }

        return this.enMission; // Supposant que vous avez un champ boolean enMission

    }

}