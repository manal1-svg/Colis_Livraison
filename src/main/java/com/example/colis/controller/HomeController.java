package com.example.colis.controller;

import com.example.colis.entity.Colis;
import com.example.colis.entity.StatutColis;
import com.example.colis.entity.User;
import com.example.colis.service.ColisService;
import com.example.colis.service.TrackingService;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Optional;

@Controller
public class HomeController {

    private final ColisService colisService;
    private final TrackingService trackingService;

    public HomeController(ColisService colisService, TrackingService trackingService) {
        this.colisService = colisService;
        this.trackingService = trackingService;
    }

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
    public String suivreColis(@RequestParam String codeSuivi, Model model) {
        Optional<Colis> colis = colisService.findByCode(codeSuivi);

        if (colis.isPresent()) {
            model.addAttribute("colis", colis.get());
            model.addAttribute("etapes", trackingService.getPackageSteps(colis.get().getStatut()));
            model.addAttribute("progression", trackingService.calculateProgress(colis.get().getStatut()));
            return "suivi";
        } else {
            return "redirect:/?error=Code+de+suivi+non+trouvé";
        }
    }

    @GetMapping("/suivi/{code}")
    public String suivreColisDetails(@PathVariable String code, Model model) {
        Colis colis = colisService.findByCode(code)
                .orElseThrow(() -> new IllegalArgumentException("Colis non trouvé"));

        model.addAttribute("colis", colis);
        model.addAttribute("etapes", trackingService.getPackageSteps(colis.getStatut()));
        model.addAttribute("progression", trackingService.calculateProgress(colis.getStatut()));
        return "suivi";
    }

    @PostMapping("/annuler/{code}")
    public String annulerLivraison(@PathVariable String code) {
        trackingService.cancelDelivery(code);
        return "redirect:/suivi/" + code;
    }

    @GetMapping("/nouveau")
    public String nouveauColisForm(HttpSession session, Model model,
                                   @RequestParam(name = "redirect", required = false) String redirectUrl) {
        User user = (User) session.getAttribute("user");

        if (user == null) {
            // Stocke l'URL originale pour redirection après login
            String redirect = (redirectUrl != null) ? redirectUrl : "/nouveau";
            return "redirect:/client/register?redirect=" + redirect;
        }

        model.addAttribute("colis", new Colis());
        return "nouveau-colis";
    }

    @PostMapping("/nouveau")
    public String creerColis(@ModelAttribute Colis colis,
                             HttpSession session,
                             RedirectAttributes redirectAttributes) {
        User user = (User) session.getAttribute("user");
        if (user == null) {
            return "redirect:/login?redirect=/nouveau";
        }

        colisService.createColis(colis, user);
        redirectAttributes.addFlashAttribute("success", "Colis créé avec succès!");
        return "redirect:/client/dashboard";
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
}