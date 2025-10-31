package com.example.colis.entity;

public class TrackingStep {
    private String nom;
    private String date;
    private String description;
    private boolean active;

    public TrackingStep(String nom, String date, String description, boolean active) {
        this.nom = nom;
        this.date = date;
        this.description = description;
        this.active = active;
    }

    // Getters et Setters
    public String getNom() {
        return nom;
    }

    public void setNom(String nom) {
        this.nom = nom;
    }

    public String getDate() {
        return date;
    }

    public void setDate(String date) {
        this.date = date;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }
}