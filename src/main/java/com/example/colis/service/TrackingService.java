package com.example.colis.service;

import com.example.colis.entity.Colis;
import com.example.colis.entity.StatutColis;
import com.example.colis.entity.TrackingStep;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

@Service
public class TrackingService {

    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("dd MMM yyyy HH:mm");

    public List<TrackingStep> getPackageSteps(StatutColis status) {
        List<TrackingStep> steps = new ArrayList<>();
        LocalDateTime now = LocalDateTime.now();

        // Étape 1: Enregistrement (toujours présente)
        steps.add(new TrackingStep(
                "Colis enregistré",
                now.minusDays(3).format(DATE_FORMATTER),
                "Votre colis a été enregistré dans notre système",
                status.ordinal() >= StatutColis.ENREGISTRE.ordinal()
        ));

        // Étape 2: En transit
        if (status.ordinal() >= StatutColis.EN_TRANSIT.ordinal()) {
            steps.add(new TrackingStep(
                    "Colis en transit",
                    now.minusDays(2).format(DATE_FORMATTER),
                    "Votre colis est en cours de transport vers le centre de distribution",
                    status.ordinal() >= StatutColis.EN_TRANSIT.ordinal()
            ));
        }

        // Étape 3: En livraison
        if (status.ordinal() >= StatutColis.EN_LIVRAISON.ordinal()) {
            steps.add(new TrackingStep(
                    "Colis en livraison",
                    now.minusDays(1).format(DATE_FORMATTER),
                    "Votre colis est en cours de livraison",
                    status.ordinal() >= StatutColis.EN_LIVRAISON.ordinal()
            ));
        }

        // Étape 4: Livré
        if (status == StatutColis.LIVRE) {
            steps.add(new TrackingStep(
                    "Colis livré",
                    now.format(DATE_FORMATTER),
                    "Votre colis a été livré avec succès",
                    true
            ));
        }

        // Étape 5: Annulé (si applicable)
        if (status == StatutColis.ANNULE) {
            steps.add(new TrackingStep(
                    "Colis annulé",
                    now.format(DATE_FORMATTER),
                    "Votre colis a été annulé",
                    false
            ));
        }

        return steps;
    }

    public int calculateProgress(StatutColis status) {
        switch (status) {
            case ENREGISTRE:
                return 25;
            case EN_TRANSIT:
                return 50;
            case EN_LIVRAISON:
                return 75;
            case LIVRE:
                return 100;
            case ANNULE:
                return 0;
            default:
                return 0;
        }
    }

    public void cancelDelivery(String trackingCode) {
        // Cette méthode serait implémentée pour annuler un colis
        // La logique réelle dépendrait de votre application
    }
}