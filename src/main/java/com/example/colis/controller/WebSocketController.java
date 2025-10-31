package com.example.colis.controller;

import com.example.colis.entity.Colis;
import com.example.colis.service.ColisService;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.SendTo;
import org.springframework.stereotype.Controller;

@Controller
public class WebSocketController {

    private final ColisService colisService;

    public WebSocketController(ColisService colisService) {
        this.colisService = colisService;
    }

    @MessageMapping("/track") // /app/track (configuré dans WebSocketConfig)
    @SendTo("/topic/status") // Les clients souscrivent à ce topic
    public Colis trackPackage(String trackingCode) {
        return colisService.findByCode(trackingCode)
                .orElseThrow(() -> new IllegalArgumentException("Colis non trouvé"));
    }

    @MessageMapping("/notify")
    @SendTo("/topic/notifications")
    public String sendNotification(String message) {
        return "Notification: " + message;
    }
}