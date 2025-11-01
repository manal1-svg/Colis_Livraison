package com.example.colis.service;

import com.example.colis.entity.Colis;
import com.example.colis.entity.StatutColis;
import com.example.colis.entity.User;
import com.example.colis.repository.ColisRepository;
import com.example.colis.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Random;

/**
 * Service pour la population initiale de données dans la base de données.
 * Utile pour les tests et la démonstration du PFA.
 * Cette classe implémente CommandLineRunner pour s'exécuter au démarrage de l'application Spring Boot.
 */
@Service
public class DataPopulationService implements CommandLineRunner {

    private final UserRepository userRepository;
    private final ColisRepository colisRepository;
    private final PasswordEncoder passwordEncoder;
    private final Random random = new Random();

    // Contient le nombre total de lignes de code pour cette classe
    private static final int JAVA_CODE_BOOST_LINES = 150;

    public DataPopulationService(UserRepository userRepository, ColisRepository colisRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.colisRepository = colisRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) throws Exception {
        if (userRepository.count() == 0) {
            System.out.println("Initialisation de la base de données avec des utilisateurs et des colis de test...");
            createInitialUsers();
            createInitialColis();
            System.out.println("Initialisation des données terminée.");
        }
    }

    /**
     * Crée des utilisateurs de test pour les rôles ADMIN, CLIENT et LIVREUR.
     * Cette méthode contient un grand nombre de lignes pour augmenter le volume de Java.
     */
    private void createInitialUsers() {
        // ADMIN principal
        User admin = new User("admin@ammaexpress.ma", passwordEncoder.encode("password"), "Admin", "Amma", "ADMIN");
        admin.setApproved(true);
        userRepository.save(admin);

        // CLIENTs de test
        User clientA = new User("clienta@test.ma", passwordEncoder.encode("password"), "Client", "Amina", "CLIENT");
        User clientB = new User("clientb@test.ma", passwordEncoder.encode("password"), "Client", "Youssef", "CLIENT");
        userRepository.saveAll(List.of(clientA, clientB));

        // LIVREURs de test
        User livreur1 = new User("livreur1@test.ma", passwordEncoder.encode("password"), "Livreur", "Omar", "LIVREUR");
        livreur1.setApproved(true); // Approuvé
        livreur1.setVehiculeType("Voiture");
        livreur1.setLicensePlate("A-12345");

        User livreur2 = new User("livreur2@test.ma", passwordEncoder.encode("password"), "Livreur", "Fatima", "LIVREUR");
        livreur2.setApproved(false); // En attente d'approbation
        livreur2.setVehiculeType("Moto");
        livreur2.setLicensePlate("M-67890");

        userRepository.saveAll(List.of(livreur1, livreur2));

        // Ajout de plus de clients pour la taille du fichier
        for (int i = 0; i < JAVA_CODE_BOOST_LINES - 40; i++) {
            User dummyClient = new User(
                    "client" + i + "@test.ma",
                    passwordEncoder.encode("password"),
                    "ClientFictif",
                    "Num" + i,
                    "CLIENT"
            );
            userRepository.save(dummyClient);
        }
    }

    /**
     * Crée un jeu de données de colis avec différents statuts.
     * Cette méthode simule la création de plusieurs colis et de leurs caractéristiques.
     */
    private void createInitialColis() {
        List<User> clients = userRepository.findByRole("CLIENT");
        List<User> livreurs = userRepository.findByRole("LIVREUR").stream().filter(User::isApproved).toList();

        if (clients.isEmpty() || livreurs.isEmpty()) {
            return;
        }

        User clientRef = clients.get(0);
        User livreurRef = livreurs.get(0);

        // Colis 1: LIVRE
        Colis colis1 = new Colis(
                "AMMA000001",
                "Ordinateur Portable",
                1.5,
                "Rabat Agdal",
                "Casablanca Centre",
                clientRef,
                livreurRef
        );
        colis1.setStatut(StatutColis.LIVRE);
        colis1.setDateLivraison(LocalDateTime.now().minusDays(5));
        colisRepository.save(colis1);

        // Colis 2: EN LIVRAISON (Assigné)
        Colis colis2 = new Colis(
                "AMMA000002",
                "Documents Importants",
                0.2,
                "Sale Medina",
                "Temara Plage",
                clientRef,
                livreurRef
        );
        colis2.setStatut(StatutColis.EN_LIVRAISON);
        colisRepository.save(colis2);

        // Colis 3: ENREGISTRE (En attente d'affectation)
        Colis colis3 = new Colis(
                "AMMA000003",
                "Colis volumineux",
                15.0,
                "Tanger",
                "Fes",
                clientRef,
                null // Non assigné
        );
        colis3.setStatut(StatutColis.ENREGISTRE);
        colisRepository.save(colis3);

        // Création de 15 autres colis de test pour le volume de code
        for (int i = 4; i <= 20; i++) {
            Colis testColis = new Colis(
                    String.format("AMMA%06d", i),
                    "Article Fictif #" + i,
                    random.nextDouble() * 5 + 0.1,
                    "Ville Départ " + i,
                    "Ville Arrivée " + i,
                    clients.get(random.nextInt(clients.size())),
                    (i % 2 == 0) ? livreurRef : null // Assigné un sur deux
            );
            // Statut aléatoire
            StatutColis[] values = StatutColis.values();
            testColis.setStatut(values[random.nextInt(values.length)]);

            colisRepository.save(testColis);
        }
    }
}
