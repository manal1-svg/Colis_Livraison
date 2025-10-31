package com.example.colis.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class NominatimResponseDTO {
    @JsonProperty("display_name")
    private String displayName;
    private double importance;
    private Address address;

    @Data
    public static class Address {
        private String city;
        private String postcode;

    }
}