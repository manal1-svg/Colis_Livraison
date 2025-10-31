package com.example.colis.controller;

import com.example.colis.entity.User;
import com.example.colis.repository.UserRepository;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class AuthController {

    private final UserRepository userRepository;

    public AuthController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    // Page de login
    @GetMapping("/login")
    public String loginPage(@RequestParam(name = "error", required = false) String error,
                            Model model) {
        if (error != null) {
            model.addAttribute("error", "Email ou mot de passe incorrect");
        }
        return "login";
    }

    // Traitement du login
    @PostMapping("/login")
    public String login(@RequestParam String email,
                        @RequestParam String password,
                        HttpSession session,
                        Model model) {

        User user = userRepository.findByEmail(email);
        if (user != null && user.getPassword().equals(password)) {
            session.setAttribute("user", user);

            // Redirection différente pour l'admin
            if ("admin@amana.ma".equalsIgnoreCase(email)) {
                return "redirect:/admin/dashboard";
            }
            return "redirect:/dashboard";
        } else {
            return "redirect:/login?error=true";
        }
    }

    // Page d'inscription
    @GetMapping("/register")
    public String registerPage() {
        return "register";
    }

    // Traitement de l'inscription
    @PostMapping("/register")
    public String register(@RequestParam String email,
                           @RequestParam String password,
                           @RequestParam String fullName,
                           Model model) {

        if (userRepository.findByEmail(email) != null) {
            model.addAttribute("error", "Cet email est déjà utilisé");
            return "register";
        }

        User user = new User();
        user.setEmail(email);
        user.setPassword(password);
        user.setFullName(fullName);

        userRepository.save(user);

        return "redirect:/login?registered=true";
    }

    // Déconnexion
    @GetMapping("/logout")
    public String logout(HttpSession session) {
        session.invalidate();
        return "redirect:/login?logout=true";
    }
}