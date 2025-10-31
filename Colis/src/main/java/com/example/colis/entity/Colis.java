package com.example.colis.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Setter
@Getter
@Entity
public class Colis {
    // Getters et Setters
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String codeSuivi;
    private String expediteur;
    private String destinataire;
    private String adresseLivraison;
    private double poids;

    @Enumerated(EnumType.STRING)
    private StatutColis statut;

    private LocalDateTime dateEnregistrement;
    private LocalDateTime dateLivraisonPrevue;

    // Constructeurs
    public Colis() {
        // Constructeur par défaut nécessaire pour JPA
    }



    public Colis(String codeSuivi, String expediteur, String destinataire,
                 String adresseLivraison, double poids,
                 LocalDateTime dateEnregistrement,
                 LocalDateTime dateLivraisonPrevue,
                 StatutColis statut) {
        this.codeSuivi = codeSuivi;
        this.expediteur = expediteur;
        this.destinataire = destinataire;
        this.adresseLivraison = adresseLivraison;
        this.poids = poids;
        this.dateEnregistrement = dateEnregistrement;
        this.dateLivraisonPrevue = dateLivraisonPrevue;
        this.statut = statut;
    }

}