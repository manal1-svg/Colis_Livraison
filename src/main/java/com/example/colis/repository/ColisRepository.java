package com.example.colis.repository;

import com.example.colis.entity.Colis;
import com.example.colis.entity.StatutColis;
import com.example.colis.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface ColisRepository extends JpaRepository<Colis, Long> {
    // Modifié pour utiliser StatutColis au lieu de String
    long countByStatut(StatutColis statut);

    // Ajout de la méthode manquante findByCodeSuivi
    Optional<Colis> findByCodeSuivi(String codeSuivi);

    List<Colis> findTop5ByOrderByDateEnregistrementDesc();

    List<Colis> findByStatut(StatutColis statut);

    List<Colis> findByLivreurAndStatutIn(User livreur, List<StatutColis> statuts);

    List<Colis> findByLivreurAndStatut(User livreur, StatutColis statut);

    List<Colis> findByExpediteurUserOrderByDateCreationDesc(User expediteur);

    List<Colis> findByExpediteurUser(User user);

    List<Colis> findByLivreur(User livreur);

    long countByExpediteurUser(User expediteur);

    long countByExpediteurUserAndStatut(User expediteur, StatutColis statut);

    long countByExpediteurUserAndStatutIn(User expediteur, List<StatutColis> statuts);

    List<Colis> findByStatutAndLivreurIsNull(StatutColis statut);

    List<Colis> findTop5ByExpediteurUserOrderByDateCreationDesc(User user);

    List<Colis> findByExpediteurUserAndStatut(User user, StatutColis statut);

    List<Colis> findByExpediteurUserAndStatutIn(User user, List<StatutColis> statuts);

    boolean existsByLivreurAndStatutIn(User livreur, List<StatutColis> statuts);

    @Query("SELECT DISTINCT c.adresseLivraison FROM Colis c WHERE c.expediteurUser.id = :userId AND c.adresseLivraison LIKE %:query% ORDER BY c.dateCreation DESC")
    List<String> findRecentAddresses(@Param("userId") String userId, @Param("query") String query);



}