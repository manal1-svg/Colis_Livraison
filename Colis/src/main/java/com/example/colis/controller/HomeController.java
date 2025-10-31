package com.example.colis.controller;

import com.example.colis.entity.Colis;
import com.example.colis.entity.StatutColis;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@Controller
public class HomeController {

    // Simulation de base de données en mémoire
    private final List<Colis> colisList = new ArrayList<>(Arrays.asList(
            new Colis("AMNA123456789", "Amyra Mouhib", "Manal Ejjebli",
                    "123 Rue Hassan II, Casablanca", 2.5,
                    LocalDateTime.now().minusDays(3),
                    LocalDateTime.now().plusDays(1),
                    StatutColis.EN_LIVRAISON),

            new Colis("AMNA987654321", "Fatima Zahra", "Nabil Dirar",
                    "456 Avenue Mohammed V, Rabat", 1.8,
                    LocalDateTime.now().minusDays(1),
                    LocalDateTime.now().plusDays(2),
                    StatutColis.EN_TRANSIT),

            new Colis("AMNA456789123", "Ahmed Kassi", "Samira Naji",
                    "789 Boulevard Zerktouni, Marrakech", 3.2,
                    LocalDateTime.now().minusHours(12),
                    LocalDateTime.now().plusDays(3),
                    StatutColis.ENREGISTRE)
    ));

    @GetMapping("/")
    public String home(Model model,
                       @RequestParam(name = "error", required = false) String error) {
        model.addAttribute("pageTitle", "Colis - Suivi de vos envois");
        if (error != null) {
            model.addAttribute("error", error);
        }
        return "home";
    }

    @PostMapping("/suivi")
    public String suivreColis(@RequestParam String codeSuivi) {
        Optional<Colis> colis = colisList.stream()
                .filter(c -> c.getCodeSuivi().equalsIgnoreCase(codeSuivi))
                .findFirst();

        if (colis.isPresent()) {
            return "redirect:/suivi/" + codeSuivi;
        } else {
            return "redirect:/?error=Code+de+suivi+non+trouvé";
        }
    }

    @GetMapping("/suivi/{code}")
    public String suivreColisDetails(@PathVariable String code, Model model) {
        Optional<Colis> colisOpt = colisList.stream()
                .filter(c -> c.getCodeSuivi().equalsIgnoreCase(code))
                .findFirst();

        if (colisOpt.isEmpty()) {
            System.out.println("Colis non trouvé !");
            return "redirect:/?error=Code+de+suivi+non+trouvé";
        }

        Colis colis = colisOpt.get();
        System.out.println("Colis trouvé : " + colis.getCodeSuivi());
        model.addAttribute("colis", colis);
        model.addAttribute("etapes", getEtapesColis(colis.getStatut()));
        model.addAttribute("progression", calculateProgression(colis.getStatut()));
        return "suivi";
    }


    @PostMapping("/annuler/{code}")
    public String annulerLivraison(@PathVariable String code) {
        colisList.stream()
                .filter(c -> c.getCodeSuivi().equalsIgnoreCase(code))
                .findFirst()
                .ifPresent(colis -> colis.setStatut(StatutColis.ANNULE));

        return "redirect:/suivi/" + code;
    }

    @GetMapping("/nouveau")
    public String nouveauColisForm(Model model) {
        model.addAttribute("colis", new Colis());
        return "nouveau-colis";
    }

    @PostMapping("/nouveau")
    public String creerColis(@ModelAttribute Colis colis, Model model) {
        // Générer un code de suivi unique
        String codeSuivi = "AMNA" + System.currentTimeMillis();
        colis.setCodeSuivi(codeSuivi);
        colis.setDateEnregistrement(LocalDateTime.now());
        colis.setDateLivraisonPrevue(LocalDateTime.now().plusDays(3));
        colis.setStatut(StatutColis.ENREGISTRE);

        // Ajouter à la liste (en production, utiliser repository.save())
        colisList.add(colis);

        model.addAttribute("codeSuivi", codeSuivi);
        return "confirmation-colis";
    }

    @GetMapping("/about")
    public String aboutPage(Model model) {
        model.addAttribute("pageTitle", "À propos - Amana Express");
        return "about";
    }

    @GetMapping("/contact")
    public String contactPage(Model model) {
        model.addAttribute("pageTitle", "Contact - Amana Express");
        return "contact";
    }






    private List<StatutColis> getEtapesColis(StatutColis statutActuel) {
        List<StatutColis> toutesEtapes = Arrays.asList(
                StatutColis.ENREGISTRE,
                StatutColis.EN_TRANSIT,
                StatutColis.EN_LIVRAISON,
                StatutColis.LIVRE
        );

        // Si annulé, on montre toutes les étapes jusqu'à annulation
        if (statutActuel == StatutColis.ANNULE) {
            toutesEtapes = Arrays.asList(
                    StatutColis.ENREGISTRE,
                    StatutColis.ANNULE
            );
        }

        return toutesEtapes.subList(0, toutesEtapes.indexOf(statutActuel) + 1);
    }

    private int calculateProgression(StatutColis statut) {
        return switch (statut) {
            case ENREGISTRE -> 25;
            case EN_TRANSIT -> 50;
            case EN_LIVRAISON -> 75;
            case LIVRE, ANNULE -> 100;
        };
    }
}

