package com.example.colis.service;

import com.example.colis.entity.Colis;
import com.example.colis.entity.StatutColis;
import com.example.colis.entity.User;
import com.example.colis.repository.ColisRepository;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class LivreurService {

    private final ColisRepository colisRepository;

    public LivreurService(ColisRepository colisRepository) {
        this.colisRepository = colisRepository;
    }

    public List<Colis> getAssignedPackages(User livreur) {
        return colisRepository.findByLivreur(livreur);
    }

    public List<Colis> getAvailablePackages() {
        return colisRepository.findByStatutAndLivreurIsNull(StatutColis.ENREGISTRE);
    }

    public void accepterColis(Long colisId, User livreur) {
        Colis colis = colisRepository.findById(colisId)
                .orElseThrow(() -> new IllegalArgumentException("Colis non trouvé"));

        // Vérifier que le colis est bien en attente
        if (colis.getStatut() != StatutColis.ENREGISTRE) {
            throw new IllegalStateException("Ce colis n'est pas disponible pour acceptation");
        }

        colis.setLivreur(livreur);
        colis.setStatut(StatutColis.EN_TRANSIT);
        colisRepository.save(colis);
    }

    public void mettreEnLivraison(Long colisId) {
        Colis colis = colisRepository.findById(colisId)
                .orElseThrow(() -> new IllegalArgumentException("Colis non trouvé"));

        if (colis.getStatut() != StatutColis.EN_TRANSIT) {
            throw new IllegalStateException("Seuls les colis en transit peuvent être mis en livraison");
        }

        colis.setStatut(StatutColis.EN_LIVRAISON);
        colisRepository.save(colis);
    }

    public void livrerColis(Long colisId) {
        Colis colis = colisRepository.findById(colisId)
                .orElseThrow(() -> new IllegalArgumentException("Colis non trouvé"));

        if (colis.getStatut() != StatutColis.EN_LIVRAISON) {
            throw new IllegalStateException("Seuls les colis en livraison peuvent être marqués comme livrés");
        }

        colis.setStatut(StatutColis.LIVRE);
        colis.setDateLivraison(LocalDateTime.now());
        colisRepository.save(colis);
    }

    public void refuserColis(Long colisId, User livreur) {
        Colis colis = colisRepository.findById(colisId)
                .orElseThrow(() -> new IllegalArgumentException("Colis non trouvé"));

        // Vérifier que le livreur est bien celui assigné
        if (!livreur.equals(colis.getLivreur())) {
            throw new IllegalStateException("Vous n'êtes pas assigné à ce colis");
        }

        colis.setLivreur(null);
        colis.setStatut(StatutColis.ENREGISTRE);
        colisRepository.save(colis);
    }
}