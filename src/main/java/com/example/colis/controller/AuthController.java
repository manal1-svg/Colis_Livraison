package com.example.colis.controller;

import com.example.colis.entity.User;
import com.example.colis.service.AuthService;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Optional;

@Controller
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    // Affichage de la page de connexion
    @GetMapping("/login")
    public String loginPage(@RequestParam(name = "error", required = false) String error,
                            @RequestParam(name = "logout", required = false) String logout,
                            @RequestParam(name = "registered", required = false) String registered,
                            Model model) {
        if (error != null) {
            model.addAttribute("error", "Email ou mot de passe incorrect");
        }
        if (logout != null) {
            model.addAttribute("message", "Vous avez été déconnecté avec succès");
        }
        if (registered != null) {
            model.addAttribute("message", "Inscription réussie. Connectez-vous.");
        }
        return "login";
    }

    // Traitement du login
    @PostMapping("/login")
    public String login(@RequestParam String email,
                        @RequestParam String password,
                        HttpSession session,
                        RedirectAttributes redirectAttributes) {

        Optional<User> userOptional = authService.authenticate(email, password);

        if (userOptional.isEmpty()) {
            redirectAttributes.addAttribute("error", true);
            return "redirect:/login";
        }

        User user = userOptional.get();
        session.setAttribute("user", user);

        // Redirection basée sur le rôle
        return switch(user.getRole()) {
            case "ADMIN" -> "redirect:/admin/dashboard";
            case "LIVREUR" -> "redirect:/livreur/dashboard";
            default -> "redirect:/client/dashboard";
        };
    }

    // Affichage formulaire d'inscription générique
    @GetMapping("/register")
    public String registerPage(Model model) {
        model.addAttribute("user", new User());
        return "register";
    }

    // Traitement de l'inscription générique (inclut livreur)
    @PostMapping("/register")
    public String register(@ModelAttribute User user,
                           @RequestParam String passwordConfirm,
                           @RequestParam(required = false) String vehiculeType,
                           @RequestParam(required = false) String licensePlate,
                           @RequestParam(required = false) String phoneNumber,
                           Model model) {

        try {
            if ("LIVREUR".equalsIgnoreCase(user.getRole())) {
                user.setVehiculeType(vehiculeType);
                user.setLicensePlate(licensePlate);
                user.setPhoneNumber(phoneNumber);
            }

            authService.registerUser(user, passwordConfirm);
            return "redirect:/login?registered=true";
        } catch (IllegalArgumentException e) {
            model.addAttribute("error", e.getMessage());
            return "register";
        }
    }

    // Formulaire d'inscription spécifique client
    @GetMapping("/client/register")
    public String clientRegisterForm(Model model) {
        model.addAttribute("user", new User());
        model.addAttribute("userType", "client");
        return "client/register";
    }

    // Traitement d'inscription client
    @PostMapping("/client/register")
    public String registerClient(@ModelAttribute User user,
                                 @RequestParam String passwordConfirm,
                                 Model model) {
        try {
            user.setRole("CLIENT");
            authService.registerUser(user, passwordConfirm);
            return "redirect:/login?registered=true";
        } catch (IllegalArgumentException e) {
            model.addAttribute("error", e.getMessage());
            return "client/register";
        }
    }

    @GetMapping("/livreur/register")
    public String livreurRegisterForm(Model model) {
        model.addAttribute("user", new User());
        return "livreur/register"; // Cette vue correspond à votre page d'inscription livreur
    }

    @PostMapping("/livreur/register")
    public String registerLivreur(@ModelAttribute User user,
                                  @RequestParam String passwordConfirm,
                                  @RequestParam String vehiculeType,
                                  @RequestParam String licensePlate,
                                  @RequestParam String phoneNumber,
                                  Model model) {

        try {
            user.setRole("LIVREUR");
            user.setVehiculeType(vehiculeType);
            user.setLicensePlate(licensePlate);
            user.setPhoneNumber(phoneNumber);

            authService.registerUser(user, passwordConfirm);
            return "redirect:/login?registered=true&role=livreur";
        } catch (IllegalArgumentException e) {
            model.addAttribute("error", e.getMessage());
            return "livreur/register";
        }
    }

    // Déconnexion
    @GetMapping("/logout")
    public String logout(HttpSession session) {
        session.invalidate();
        return "redirect:/login?logout=true";
    }
}
