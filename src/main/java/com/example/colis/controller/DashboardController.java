package com.example.colis.controller;

import com.example.colis.entity.Colis;
import com.example.colis.entity.StatutColis;
import com.example.colis.entity.User;
import com.example.colis.repository.ColisRepository;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.List;

@Controller
@RequestMapping("/client")
public class DashboardController {

    private final ColisRepository colisRepository;

    public DashboardController(ColisRepository colisRepository) {
        this.colisRepository = colisRepository;
    }

    @GetMapping("/dashboard")
    public String dashboard(HttpSession session, Model model) {
        User client = (User) session.getAttribute("user");

        if (client == null || !"CLIENT".equals(client.getRole())) {
            return "redirect:/login";
        }

        // Récupérer les colis du client
        List<Colis> colisRecents = colisRepository.findTop5ByExpediteurUserOrderByDateCreationDesc(client);
        List<Colis> enAttente = colisRepository.findByExpediteurUserAndStatut(client, StatutColis.ENREGISTRE);
        List<Colis> enCours = colisRepository.findByExpediteurUserAndStatutIn(
                client,
                List.of(StatutColis.EN_TRANSIT, StatutColis.EN_LIVRAISON)
        );
        List<Colis> livres = colisRepository.findByExpediteurUserAndStatut(client, StatutColis.LIVRE);

        // Récupérer le dernier colis pour afficher le code de suivi
        Colis dernierColis = colisRecents.isEmpty() ? null : colisRecents.get(0);

        model.addAttribute("client", client);
        model.addAttribute("colisRecents", colisRecents);
        model.addAttribute("enAttente", enAttente);
        model.addAttribute("enCours", enCours);
        model.addAttribute("livres", livres);
        model.addAttribute("dernierColis", dernierColis);

        return "client/dashboard";
    }
}