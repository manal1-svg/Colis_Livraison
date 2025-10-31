package com.example.colis.controller;

import com.example.colis.entity.User;
import com.example.colis.service.ColisService;
import com.example.colis.service.DashboardService;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/client/v2")
public class ClientController {

    private final ColisService colisService;
    private final DashboardService dashboardService;

    public ClientController(ColisService colisService, DashboardService dashboardService) {
        this.colisService = colisService;
        this.dashboardService = dashboardService;
    }

    @GetMapping("/dashboard")
    public String dashboard(HttpSession session, Model model) {
        User client = (User) session.getAttribute("user");
        if (client == null) {
            return "redirect:/login";
        }

        model.addAttribute("colisList", colisService.findColisByUser(client));
        return "client/dashboard";
    }
}