//package com.example.colis.controller;
//
//import com.example.colis.entity.Colis;
//import com.example.colis.service.ColisService;
//import org.springframework.stereotype.Controller;
//import org.springframework.ui.Model;
//import org.springframework.web.bind.annotation.GetMapping;
//import org.springframework.web.bind.annotation.PostMapping;
//import org.springframework.web.bind.annotation.RequestParam;
//
//import java.util.Optional;
//
//@Controller
//public class TrackingController {
//
//    private final ColisService colisService;
//
//    public TrackingController(ColisService colisService) {
//        this.colisService = colisService;
//    }
//
//    @GetMapping("/suivi")
//    public String trackingForm() {
//        return "tracking-form";
//    }
//
//    @PostMapping("/suivi")
//    public String trackPackage(@RequestParam String codeSuivi, Model model) {
//        Optional<Colis> colis = colisService.findByCode(codeSuivi);
//
//        if (colis.isPresent()) {
//            model.addAttribute("colis", colis.get());
//            return "tracking-result";
//        } else {
//            model.addAttribute("error", "Aucun colis trouvé avec ce numéro de suivi");
//            return "tracking-form";
//        }
//    }
//}