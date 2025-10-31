package com.example.colis.service;

import com.example.colis.entity.StatutColis;
import com.example.colis.entity.User;
import com.example.colis.repository.ColisRepository;
import com.example.colis.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class DashboardService {

    private final ColisRepository colisRepository;
    private final UserRepository userRepository;

    public DashboardService(ColisRepository colisRepository, UserRepository userRepository) {
        this.colisRepository = colisRepository;
        this.userRepository = userRepository;
    }

    public Map<String, Object> getAdminStatistics() {
        Map<String, Object> stats = new HashMap<>();

        stats.put("colisCount", colisRepository.count());
        stats.put("usersCount", userRepository.count());
        stats.put("enregistreCount", colisRepository.countByStatut(StatutColis.ENREGISTRE));
        stats.put("transitCount", colisRepository.countByStatut(StatutColis.EN_TRANSIT));
        stats.put("livraisonCount", colisRepository.countByStatut(StatutColis.EN_LIVRAISON));
        stats.put("livreCount", colisRepository.countByStatut(StatutColis.LIVRE));
        stats.put("annuleCount", colisRepository.countByStatut(StatutColis.ANNULE));

        return stats;
    }

    public Map<String, Object> getClientStatistics(User client) {
        Map<String, Object> stats = new HashMap<>();

        stats.put("totalColis", colisRepository.countByExpediteurUser(client));
        stats.put("enregistreCount", colisRepository.countByExpediteurUserAndStatut(client, StatutColis.ENREGISTRE));
        stats.put("transitCount", colisRepository.countByExpediteurUserAndStatut(client, StatutColis.EN_TRANSIT));
        stats.put("livraisonCount", colisRepository.countByExpediteurUserAndStatut(client, StatutColis.EN_LIVRAISON));
        stats.put("livreCount", colisRepository.countByExpediteurUserAndStatut(client, StatutColis.LIVRE));
        stats.put("annuleCount", colisRepository.countByExpediteurUserAndStatut(client, StatutColis.ANNULE));

        return stats;
    }
}