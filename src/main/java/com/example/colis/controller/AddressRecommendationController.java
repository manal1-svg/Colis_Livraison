//package com.example.colis.controller;
//
//import com.example.colis.dto.AddressSuggestionDTO;
//import com.example.colis.dto.NominatimResponseDTO;
//import com.example.colis.entity.User;
//import com.example.colis.repository.ColisRepository;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.http.*;
//import org.springframework.web.bind.annotation.*;
//import org.springframework.web.client.RestTemplate;
//
//import java.net.URLEncoder;
//import java.nio.charset.StandardCharsets;
//import java.util.*;
//import java.util.stream.Collectors;
//import java.util.stream.Stream;
//
//@RestController
//@RequestMapping("/api/address")
//public class AddressRecommendationController {
//
//    @Value("${nominatim.url}")
//    private String nominatimUrl;
//
//    @Value("${nominatim.email}")
//    private String nominatimEmail;
//
//    private final ColisRepository colisRepository;
//    private final RestTemplate restTemplate;
//
//    public AddressRecommendationController(ColisRepository colisRepository, RestTemplate restTemplate) {
//        this.colisRepository = colisRepository;
//        this.restTemplate = restTemplate;
//    }
//
//    @GetMapping("/recommendations")
//    public ResponseEntity<List<AddressSuggestionDTO>> getRecommendations(
//            @RequestParam String query,
//            @AuthenticationPrincipal User user,  // Utilisez l'utilisateur authentifié
//            @RequestHeader(value = "User-Agent", required = false) String userAgent) {
//
//        if (user == null) {
//            return ResponseEntity.ok(Collections.emptyList());
//        }
//
//        // 1. Historique utilisateur
//        List<AddressSuggestionDTO> historySuggestions = getHistorySuggestions(user.getId().toString(), query);
//
//        // 2. Suggestions OSM
//        List<AddressSuggestionDTO> osmSuggestions = getOsmSuggestions(query, userAgent);
//
//        // 3. Combinaison et tri
//        List<AddressSuggestionDTO> combined = Stream.concat(
//                        historySuggestions.stream(),
//                        osmSuggestions.stream()
//                )
//                .sorted(Comparator.comparingDouble(AddressSuggestionDTO::getScore).reversed())
//                .limit(5)
//                .collect(Collectors.toList());
//
//        return ResponseEntity.ok(combined);
//    }
//
//    private List<AddressSuggestionDTO> getHistorySuggestions(String userId, String query) {
//        return colisRepository.findRecentAddresses(userId, query).stream()
//                .map(addr -> new AddressSuggestionDTO(addr, "history", 1.0, null, null))
//                .collect(Collectors.toList());
//    }
//
//    private List<AddressSuggestionDTO> getOsmSuggestions(String query, String userAgent) {
//        String url = String.format("%s?format=json&q=%s&countrycodes=ma&limit=5&email=%s",
//                nominatimUrl,
//                URLEncoder.encode(query, StandardCharsets.UTF_8),
//                nominatimEmail);
//
//        try {
//            HttpHeaders headers = new HttpHeaders();
//            if (userAgent != null) {
//                headers.set("User-Agent", userAgent);
//            }
//
//            ResponseEntity<NominatimResponseDTO[]> response = restTemplate.exchange(
//                    url,
//                    HttpMethod.GET,
//                    new HttpEntity<>(headers),
//                    NominatimResponseDTO[].class);
//
//            return Arrays.stream(response.getBody())
//                    .map(item -> new AddressSuggestionDTO(
//                            item.getDisplayName(),
//                            "osm",
//                            item.getImportance(),
//                            item.getAddress() != null ? item.getAddress().getCity() : null,
//                            item.getAddress() != null ? item.getAddress().getPostcode() : null
//                    ))
//                    .collect(Collectors.toList());
//        } catch (Exception e) {
//            return Collections.emptyList();
//        }
//    }
//}