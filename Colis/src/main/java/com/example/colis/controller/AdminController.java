package com.example.colis.controller;

import com.example.colis.entity.Colis;
import com.example.colis.entity.StatutColis;
import com.example.colis.entity.User;
import com.example.colis.repository.UserRepository;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequestMapping("/admin")
public class AdminController {

    private final List<Colis> colisList;
    private final UserRepository userRepository;

    public AdminController(UserRepository userRepository, List<Colis> colisList) {
        this.userRepository = userRepository;
        this.colisList = colisList;
    }

    @GetMapping("/dashboard")
    public String dashboard(HttpSession session, Model model) {
        // Vérification simple de l'admin
        User user = (User) session.getAttribute("user");
        if (user == null || !"admin@amana.ma".equalsIgnoreCase(user.getEmail())) {
            return "redirect:/login?error=Unauthorized";
        }

        model.addAttribute("colisCount", colisList.size());
        model.addAttribute("usersCount", userRepository.count());

        // Statistiques par statut
        model.addAttribute("enregistreCount", colisList.stream()
                .filter(c -> c.getStatut() == StatutColis.ENREGISTRE).count());
        model.addAttribute("transitCount", colisList.stream()
                .filter(c -> c.getStatut() == StatutColis.EN_TRANSIT).count());
        model.addAttribute("livraisonCount", colisList.stream()
                .filter(c -> c.getStatut() == StatutColis.EN_LIVRAISON).count());
        model.addAttribute("livreCount", colisList.stream()
                .filter(c -> c.getStatut() == StatutColis.LIVRE).count());
        model.addAttribute("annuleCount", colisList.stream()
                .filter(c -> c.getStatut() == StatutColis.ANNULE).count());

        return "dashboard";
    }

    @GetMapping("/colis")
    public String gestionColis(Model model) {
        model.addAttribute("colisList", colisList);
        return "colis";
    }

    @GetMapping("/colis/edit/{code}")
    public String editColisForm(@PathVariable String code, Model model) {
        Colis colis = colisList.stream()
                .filter(c -> c.getCodeSuivi().equalsIgnoreCase(code))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Colis non trouvé"));
        model.addAttribute("colis", colis);
        return "edit-colis";
    }

    @PostMapping("/colis/update")
    public String updateColis(@ModelAttribute Colis colis) {
        colisList.replaceAll(c ->
                c.getCodeSuivi().equals(colis.getCodeSuivi()) ? colis : c);
        return "redirect:/admin/colis";
    }

    @GetMapping("/colis/delete/{code}")
    public String deleteColis(@PathVariable String code) {
        colisList.removeIf(c -> c.getCodeSuivi().equalsIgnoreCase(code));
        return "redirect:/admin/colis";
    }

    @GetMapping("/users")
    public String gestionUsers(Model model) {
        model.addAttribute("users", userRepository.findAll());
        return "users";
    }
}