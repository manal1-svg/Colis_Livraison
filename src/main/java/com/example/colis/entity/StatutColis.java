package com.example.colis.entity;

import lombok.Getter;

@Getter
public enum StatutColis {
    ENREGISTRE("Enregistré"), // Le colis a été enregistré dans le système
    EN_TRANSIT("En transit"), // Le colis est en cours de transport
    EN_LIVRAISON("En livraison"), // Le colis est en cours de livraison
    LIVRE("Livré"), // Le colis a été livré avec succès
    ANNULE("Annulé");// La livraison du colis a été annulée

    // Getter pour récupérer le libellé associé au statut
    private final String label;

    StatutColis(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }

}