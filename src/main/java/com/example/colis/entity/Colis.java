package com.example.colis.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import java.time.LocalDateTime;

@Setter
@Getter
@Entity
public class Colis {
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

    private Long userId;

    @ManyToOne
    @JoinColumn(name = "expediteur_user_id")
    private User expediteurUser;

    @ManyToOne
    @JoinColumn(name = "livreur_id")
    private User livreur;

    private LocalDateTime dateEnregistrement;
    private LocalDateTime dateLivraisonPrevue;
    private LocalDateTime dateCreation;
    private LocalDateTime dateMaj;
    private LocalDateTime dateLivraison;

    // Ajoutez ceci si vous gardez la colonne adresse_complete
    @Column(name = "adresse_complete")
    private String adresseComplete;

    public Colis() {
        this.dateCreation = LocalDateTime.now();
        this.adresseComplete = ""; // Valeur par défaut
    }

    public Colis(String codeSuivi, String expediteur, String destinataire,
                 String adresseLivraison, double poids,
                 LocalDateTime dateEnregistrement,
                 LocalDateTime dateLivraisonPrevue,
                 StatutColis statut) {
        this();
        this.codeSuivi = codeSuivi;
        this.expediteur = expediteur;
        this.destinataire = destinataire;
        this.adresseLivraison = adresseLivraison;
        this.poids = poids;
        this.dateEnregistrement = dateEnregistrement;
        this.dateLivraisonPrevue = dateLivraisonPrevue;
        this.statut = statut;
        this.adresseComplete = adresseLivraison; // Mappage automatique
    }

    // Correction: getDateCreation() devrait retourner dateCreation, pas dateEnregistrement
    public LocalDateTime getDateCreation() {
        return dateCreation;
    }
}