package com.example.colis.controller;

import com.example.colis.entity.Colis;
import com.example.colis.entity.User;
import com.example.colis.service.ColisService;
import com.example.colis.service.DashboardService;
import com.example.colis.service.UserService;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequestMapping("/admin")
public class AdminController {

    private final UserService userService;
    private final ColisService colisService;
    private final DashboardService dashboardService;

    public AdminController(UserService userService, ColisService colisService, DashboardService dashboardService) {
        this.userService = userService;
        this.colisService = colisService;
        this.dashboardService = dashboardService;
    }

    @GetMapping("/dashboard")
    public String dashboard(HttpSession session, Model model) {
        User user = (User) session.getAttribute("user");

        if (user == null || !userService.isAdmin(user)) {
            return "redirect:/login?error=Unauthorized";
        }

        model.addAllAttributes(dashboardService.getAdminStatistics());
        model.addAttribute("recentColis", colisService.findRecentColis(5));
        model.addAttribute("recentUsers", userService.findRecentUsers(5));

        return "admin/dashboard";
    }

    @GetMapping("/colis")
    public String gestionColis(Model model) {
        model.addAttribute("colisList", colisService.findAllColis());
        model.addAttribute("newColis", new Colis());
        return "admin/colis";
    }

    @PostMapping("/colis/add")
    public String addColis(@ModelAttribute Colis colis) {
        colisService.createColis(colis, null); // L'admin crée un colis sans expéditeur spécifié
        return "redirect:/admin/colis";
    }

    @GetMapping("/colis/edit/{code}")
    public String editColisForm(@PathVariable String code, Model model) {
        Colis colis = colisService.findByCode(code)
                .orElseThrow(() -> new IllegalArgumentException("Colis non trouvé"));
        model.addAttribute("colis", colis);
        return "admin/edit-colis";
    }

    @PostMapping("/colis/update")
    public String updateColis(@ModelAttribute Colis colis) {
        colisService.updateColis(colis);
        return "redirect:/admin/colis";
    }

    @GetMapping("/colis/delete/{code}")
    public String deleteColis(@PathVariable String code) {
        colisService.deleteColis(code);
        return "redirect:/admin/colis";
    }

    @GetMapping("/users")
    public String gestionUsers(Model model) {
        model.addAttribute("users", userService.findAllUsers());
        model.addAttribute("newUser", new User());
        return "admin/users";
    }

    @PostMapping("/users/add")
    public String addUser(@ModelAttribute User user) {
        userService.createUser(user);
        return "redirect:/admin/users";
    }

    @GetMapping("/users/edit/{id}")
    public String editUserForm(@PathVariable Long id, Model model) {
        User user = userService.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Utilisateur non trouvé"));
        model.addAttribute("user", user);
        return "admin/edit-user";
    }

    @PostMapping("/users/update")
    public String updateUser(@ModelAttribute User user) {
        userService.updateUser(user);
        return "redirect:/admin/users";
    }

    @GetMapping("/users/delete/{id}")
    public String deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
        return "redirect:/admin/users";
    }

    @GetMapping("/users/approve/{id}")
    public String approveLivreur(@PathVariable Long id) {
        userService.approveLivreur(id);
        return "redirect:/admin/users";
    }
    @GetMapping("/livreurs")
    public String gestionLivreurs(Model model) {
        List<User> livreurs = userService.findByRole("LIVREUR");

        long actifsCount = livreurs.stream().filter(User::isApproved).count();
        long enMissionCount = livreurs.stream().filter(User::isEnMission).count();
        long inactifsCount = livreurs.size() - actifsCount;

        model.addAttribute("livreurs", livreurs);
        model.addAttribute("livreursActifsCount", actifsCount);
        model.addAttribute("livreursEnMissionCount", enMissionCount);
        model.addAttribute("livreursInactifsCount", inactifsCount);

        return "admin/livreurs";
    }
//    @GetMapping("/admin/users/search")
//    public String searchUsers(@RequestParam("query") String query, Model model) {
//        List<User> results = userService.searchUsers(query);
//        model.addAttribute("users", results);
//        return "admin/users";
//    }

}