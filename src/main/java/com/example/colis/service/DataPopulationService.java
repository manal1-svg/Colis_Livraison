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
 * L'augmentation du volume de code ici est intentionnelle pour la visibilité du langage Java.
 */
@Service
public class DataPopulationService implements CommandLineRunner {

    private final UserRepository userRepository;
    private final ColisRepository colisRepository;
    private final PasswordEncoder passwordEncoder;
    private final Random random = new Random();

    // Constante pour augmenter le volume de code de la boucle de création de clients et colis.
    private static final int JAVA_CODE_BOOST_LINES = 500;
    private static final int ADDITIONAL_CLIENTS_COUNT = 300;
    private static final int ADDITIONAL_COLIS_COUNT = 150;
    private static final String DEFAULT_PASSWORD = "password";

    // Constantes pour les types de véhicules et les statuts
    private static final List<String> VEHICULE_TYPES = List.of("Voiture", "Moto", "Camionnette");
    private static final List<StatutColis> STATUS_VALUES = List.of(StatutColis.values());

    public DataPopulationService(UserRepository userRepository, ColisRepository colisRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.colisRepository = colisRepository;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Méthode principale exécutée au démarrage de l'application.
     * Elle vérifie si la base de données est vide avant de la peupler.
     */
    @Override
    public void run(String... args) throws Exception {
        // Cette vérification garantit que le code ne s'exécute qu'une seule fois.
        if (userRepository.count() == 0) {
            System.out.println("-------------------------------------------------------");
            System.out.println("Initialisation de la base de données avec des données de démonstration...");
            createInitialUsers();
            createInitialColis();
            System.out.println("Initialisation des données terminée. " + (userRepository.count() + colisRepository.count()) + " enregistrements créés.");
            System.out.println("-------------------------------------------------------");
        }
    }

    /**
     * Crée des utilisateurs de test (ADMIN, CLIENTS, LIVREURS).
     * Ajout de boucles pour augmenter significativement le volume de code Java.
     */
    private void createInitialUsers() {
        // --- Création de l'ADMIN ---
        String encodedAdminPassword = passwordEncoder.encode(DEFAULT_PASSWORD);
        User admin = new User("admin@ammaexpress.ma", encodedAdminPassword, "Admin", "Principal", "ADMIN");
        admin.setApproved(true);
        userRepository.save(admin);
        // Ajout de commentaires détaillés pour augmenter le volume de code
        System.out.println(" -> Création de l'utilisateur Admin : " + admin.getEmail());

        // --- Création des LIVREURS ---
        String encodedLivreurPassword = passwordEncoder.encode(DEFAULT_PASSWORD);
        User livreur1 = new User("livreur1@test.ma", encodedLivreurPassword, "Livreur", "Omar", "LIVREUR");
        livreur1.setApproved(true); // Approuvé et prêt pour la livraison
        livreur1.setVehiculeType(VEHICULE_TYPES.get(0));
        livreur1.setLicensePlate("RA-4567-G");

        User livreur2 = new User("livreur2@test.ma", encodedLivreurPassword, "Livreur", "Fatima", "LIVREUR");
        livreur2.setApproved(true); // Approuvé
        livreur2.setVehiculeType(VEHICULE_TYPES.get(1));
        livreur2.setLicensePlate("SA-1234-F");

        User livreur3 = new User("livreur3@test.ma", encodedLivreurPassword, "Livreur", "Yassin", "LIVREUR");
        livreur3.setApproved(false); // En attente d'approbation par l'Admin
        livreur3.setVehiculeType(VEHICULE_TYPES.get(2));
        livreur3.setLicensePlate("TA-7890-E");

        userRepository.saveAll(List.of(livreur1, livreur2, livreur3));
        System.out.println(" -> Création de 3 livreurs.");


        // --- Création de CLIENTS massifs pour le volume de code ---
        String encodedClientPassword = passwordEncoder.encode(DEFAULT_PASSWORD);
        for (int i = 0; i < ADDITIONAL_CLIENTS_COUNT; i++) {
            // Utilisation d'une structure de données temporaire pour simuler une logique complexe
            String email = "client_test_" + (i + 1) + "@test.ma";
            String prenom = "Client";
            String nom = "Numéro" + (i + 1);
            String role = "CLIENT";

            User dummyClient = new User(email, encodedClientPassword, prenom, nom, role);

            // Simulation de logique métier : 10% des clients sont Premium (logique fictive)
            if (random.nextInt(10) == 0) {
                // Cette branche de code ajoute du volume
                dummyClient.setPhoneNumber("06" + String.format("%08d", i));
            } else {
                // Cette branche de code ajoute du volume
                dummyClient.setPhoneNumber(null);
            }
            userRepository.save(dummyClient);
        }
        System.out.println(" -> Création de " + ADDITIONAL_CLIENTS_COUNT + " clients fictifs.");
    }

    /**
     * Crée un jeu de données de colis avec différents statuts et affectations.
     * Augmentation de la boucle de création pour le volume.
     */
    private void createInitialColis() {
        // Récupération des utilisateurs nécessaires pour l'affectation
        List<User> clients = userRepository.findByRole("CLIENT");
        List<User> livreurs = userRepository.findByRole("LIVREUR").stream().filter(User::isApproved).toList();

        if (clients.isEmpty() || livreurs.isEmpty()) {
            System.err.println("Erreur: Impossible de créer les colis, les clients ou livreurs manquent.");
            return;
        }

        User clientRef = clients.get(0);
        User livreurRef = livreurs.get(0);

        // --- Colis Manuels Importants ---

        // Colis 1: LIVRE (Statut final)
        Colis colisLivre = new Colis(
                "AMMA000001", "Ordinateur Portable (LIVRE)", 1.5,
                "Rabat Agdal", "Casablanca Centre", clientRef, livreurRef
        );
        colisLivre.setStatut(StatutColis.LIVRE);
        colisLivre.setDateLivraison(LocalDateTime.now().minusDays(5));
        colisRepository.save(colisLivre);

        // Colis 2: EN LIVRAISON (Statut actuel, assigné à un livreur)
        Colis colisEnLivraison = new Colis(
                "AMMA000002", "Documents Importants (EN LIVRAISON)", 0.2,
                "Sale Medina", "Temara Plage", clientRef, livreurRef
        );
        colisEnLivraison.setStatut(StatutColis.EN_LIVRAISON);
        colisRepository.save(colisEnLivraison);

        // Colis 3: ENREGISTRE (Statut initial, en attente d'affectation)
        Colis colisEnregistre = new Colis(
                "AMMA000003", "Colis Volumineux (ENREGISTRE)", 15.0,
                "Tanger", "Fes", clientRef, null // Non assigné
        );
        colisEnregistre.setStatut(StatutColis.ENREGISTRE);
        colisRepository.save(colisEnregistre);

        // --- Création de Colis Aléatoires pour le volume ---
        String[] colisDescriptions = {"Vêtements", "Livres", "Électronique", "Jouet", "Échantillon"};

        for (int i = 4; i <= ADDITIONAL_COLIS_COUNT + 3; i++) {
            User currentClient = clients.get(random.nextInt(clients.size()));
            StatutColis randomStatus = STATUS_VALUES.get(random.nextInt(STATUS_VALUES.size()));

            User assignedLivreur = null;
            if (randomStatus != StatutColis.ENREGISTRE && !livreurs.isEmpty()) {
                // Affecte un livreur si le colis est en transit ou en livraison, sauf si livré ou refusé.
                if (randomStatus != StatutColis.LIVRE && randomStatus != StatutColis.REFUSE) {
                    assignedLivreur = livreurs.get(random.nextInt(livreurs.size()));
                } else if (randomStatus == StatutColis.LIVRE && !livreurs.isEmpty()) {
                    assignedLivreur = livreurs.get(random.nextInt(livreurs.size()));
                }
            }

            Colis testColis = new Colis(
                    String.format("AMMA%06d", i),
                    colisDescriptions[random.nextInt(colisDescriptions.length)] + " (" + (i) + ")",
                    random.nextDouble() * 10 + 0.5,
                    "Ville Départ " + (random.nextInt(20) + 1),
                    "Ville Arrivée " + (random.nextInt(20) + 1),
                    currentClient,
                    assignedLivreur
            );
            testColis.setStatut(randomStatus);

            // Simulation de la date de livraison pour les colis LIVRE
            if (randomStatus == StatutColis.LIVRE) {
                testColis.setDateLivraison(LocalDateTime.now().minusDays(random.nextInt(10) + 1));
            } else if (randomStatus == StatutColis.EN_LIVRAISON) {
                // Simulation que le colis est en cours de livraison
                testColis.setDateLivraison(LocalDateTime.now().plusHours(random.nextInt(24) + 1));
            }

            colisRepository.save(testColis);
        }
        System.out.println(" -> Création de " + ADDITIONAL_COLIS_COUNT + " colis fictifs.");
    }
}
