package com.example.colis.controller;

import com.example.colis.entity.StatutColis;
import com.example.colis.entity.User;
import com.example.colis.service.ColisService;
import com.example.colis.service.LivreurService;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequestMapping("/livreur")
public class LivreurController {

    private final LivreurService livreurService;
    private final ColisService colisService;

    public LivreurController(LivreurService livreurService, ColisService colisService) {
        this.livreurService = livreurService;
        this.colisService = colisService;
    }

    @GetMapping("/dashboard")
    public String livreurDashboard(HttpSession session, Model model) {
        User livreur = (User) session.getAttribute("user");
        if (livreur == null || !"LIVREUR".equals(livreur.getRole())) {
            return "redirect:/login";
        }

        model.addAttribute("user", livreur);
        model.addAttribute("mesColis", livreurService.getAssignedPackages(livreur));
        model.addAttribute("colisDisponibles", livreurService.getAvailablePackages());

        return "livreur/dashboard";
    }

    @PostMapping("/colis/accepter/{id}")
    public String accepterColis(@PathVariable Long id, HttpSession session, RedirectAttributes redirectAttributes) {
        try {
            User livreur = (User) session.getAttribute("user");
            livreurService.accepterColis(id, livreur);
            redirectAttributes.addFlashAttribute("success", "Colis accepté avec succès");
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("error", "Erreur: " + e.getMessage());
        }
        return "redirect:/livreur/dashboard";
    }

    @PostMapping("/colis/en-livraison/{id}")
    public String mettreEnLivraison(@PathVariable Long id, RedirectAttributes redirectAttributes) {
        try {
            livreurService.mettreEnLivraison(id);
            redirectAttributes.addFlashAttribute("success", "Colis mis en livraison");
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("error", "Erreur: " + e.getMessage());
        }
        return "redirect:/livreur/dashboard";
    }

    @PostMapping("/colis/livrer/{id}")
    public String livrerColis(@PathVariable Long id, RedirectAttributes redirectAttributes) {
        try {
            livreurService.livrerColis(id);
            redirectAttributes.addFlashAttribute("success", "Colis marqué comme livré");
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("error", "Erreur: " + e.getMessage());
        }
        return "redirect:/livreur/dashboard";
    }

    @PostMapping("/colis/refuser/{id}")
    public String refuserColis(@PathVariable Long id, HttpSession session, RedirectAttributes redirectAttributes) {
        try {
            User livreur = (User) session.getAttribute("user");
            livreurService.refuserColis(id, livreur);
            redirectAttributes.addFlashAttribute("success", "Colis refusé avec succès");
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("error", "Erreur: " + e.getMessage());
        }
        return "redirect:/livreur/dashboard";
    }


//    @PostMapping("/colis/refuser/{id}")
//    public String refuserColis(@PathVariable Long id) {
//        livreurService.refuserColis(id);
//        return "redirect:/livreur/dashboard";
//    }
//
//    @PostMapping("/colis/annuler/{id}")
//    public String annulerColis(@PathVariable Long id) {
//        livreurService.annulerColis(id);
//        return "redirect:/livreur/dashboard";
//    }
}