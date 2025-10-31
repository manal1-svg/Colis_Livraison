package com.example.colis.service;

import com.example.colis.entity.Colis;
import com.example.colis.entity.StatutColis;
import com.example.colis.entity.User;
import com.example.colis.repository.ColisRepository;
import org.springframework.stereotype.Service;
import org.springframework.messaging.simp.SimpMessagingTemplate;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Service
public class ColisService {

    private final ColisRepository colisRepository;
    private final SimpMessagingTemplate messagingTemplate;

    public ColisService(ColisRepository colisRepository , SimpMessagingTemplate messagingTemplate) {
        this.colisRepository = colisRepository;
        this.messagingTemplate = messagingTemplate;
    }


    public Colis createColis(Colis colis, User expediteur) {
        colis.setCodeSuivi(generateTrackingCode());
        colis.setDateCreation(LocalDateTime.now());
        colis.setDateEnregistrement(LocalDateTime.now());
        colis.setDateLivraisonPrevue(LocalDateTime.now().plusDays(3));
        colis.setStatut(StatutColis.ENREGISTRE);
        colis.setExpediteurUser(expediteur);
        return colisRepository.save(colis);
    }

    public Colis updateColis(Colis colis) {
        return colisRepository.save(colis);
    }

    public void deleteColis(String codeSuivi) {
        Colis colis = findByCode(codeSuivi)
                .orElseThrow(() -> new IllegalArgumentException("Colis non trouvé"));
        colisRepository.delete(colis);
    }

    public Optional<Colis> findByCode(String codeSuivi) {
        return colisRepository.findByCodeSuivi(codeSuivi);
    }

    public List<Colis> findAllColis() {
        return colisRepository.findAll();
    }

    public List<Colis> findRecentColis(int limit) {
        return colisRepository.findTop5ByOrderByDateEnregistrementDesc();
    }

    public long countColisByStatus(StatutColis status) {
        return colisRepository.countByStatut(status);
    }

    public List<Colis> findColisByUser(User user) {
        return colisRepository.findByExpediteurUser(user);
    }

    public List<Colis> findColisByLivreur(User livreur) {
        return colisRepository.findByLivreur(livreur);
    }

    public Colis updateColisStatus(String codeSuivi, StatutColis newStatus) {
        Colis colis = findByCode(codeSuivi)
                .orElseThrow(() -> new IllegalArgumentException("Colis non trouvé"));
        colis.setStatut(newStatus);
        Colis updated = colisRepository.save(colis);

        // Envoyer la mise à jour via WebSocket
        messagingTemplate.convertAndSend("/topic/status/" + codeSuivi, updated);
        messagingTemplate.convertAndSend("/topic/notifications",
                "Le colis " + codeSuivi + " a été mis à jour: " + newStatus.getLabel());

        return updated;
    }

    public List<Colis> findAvailablePackages() {
        return colisRepository.findByStatutAndLivreurIsNull(StatutColis.EN_LIVRAISON);
    }

    public List<Colis> findByExpediteurUserAndStatut(User user, StatutColis statut) {
        return colisRepository.findByExpediteurUserAndStatut(user, statut);
    }

    private String generateTrackingCode() {
        return "AMNA" + System.currentTimeMillis();
    }

    public List<Colis> findRecentColisByUser(User user, int limit) {
        return colisRepository.findTop5ByExpediteurUserOrderByDateCreationDesc(user);
    }

    public List<Colis> findColisByUserAndStatus(User user, StatutColis status) {
        return colisRepository.findByExpediteurUserAndStatut(user, status);
    }

    public List<Colis> findColisByUserAndStatusIn(User user, List<StatutColis> statuses) {
        return colisRepository.findByExpediteurUserAndStatutIn(user, statuses);
    }
}