package com.example.colis.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AddressSuggestionDTO {
    private String address;
    private String source;
    private double score;
    private String ville;
    private String codePostal;
    private Double latitude;
    private Double longitude;
}