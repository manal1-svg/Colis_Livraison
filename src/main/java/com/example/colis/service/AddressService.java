//package com.example.colis.service;
//
//import com.example.colis.ml.PythonBridgeService;
//import com.example.colis.ml.RouteOptimizer;
//import lombok.RequiredArgsConstructor;
//import org.springframework.stereotype.Service;
//
//import java.util.ArrayList;
//import java.util.Comparator;
//import java.util.List;
//import java.util.stream.Collectors;
//import java.util.stream.Stream;
//
//
//@Service
//@RequiredArgsConstructor
//public class AddressService {
//
//    private final AddressRepository addressRepo;
//    private final PythonBridgeService pythonService;
//    private final RouteOptimizer routeOptimizer;
//
//    public List<AddressSuggestion> recommendAddresses(String query, String userId) {
//        // 1. Récupérer suggestions historiques
//        List<String> history = addressRepo.findByUserId(userId);
//
//        // 2. Récupérer suggestions OSM
//        List<String> osmResults = fetchOSMResults(query);
//
//        // 3. Combiner et classer
//        List<String> allAddresses = Stream.concat(history.stream(), osmResults.stream())
//                .distinct()
//                .collect(Collectors.toList());
//
//        List<Double> scores = pythonService.getRecommendations(query, allAddresses);
//
//        // 4. Créer les suggestions classées
//        List<AddressSuggestion> suggestions = new ArrayList<>();
//        for (int i = 0; i < allAddresses.size(); i++) {
//            suggestions.add(new AddressSuggestion(allAddresses.get(i), scores.get(i)));
//        }
//
//        return suggestions.stream()
//                .sorted(Comparator.comparingDouble(AddressSuggestion::getScore).reversed())
//                .limit(5)
//                .collect(Collectors.toList());
//    }
//
//    public DeliveryRoute planDelivery(String depot, List<String> addresses) {
//        List<String> optimizedRoute = routeOptimizer.optimizeRoute(depot, addresses);
//        return new DeliveryRoute(optimizedRoute, calculateTotalDistance(optimizedRoute));
//    }
//
//    private List<String> fetchOSMResults(String query) {
//        // Implémentation utilisant ProcessBuilder pour appeler osm_helper.py
//    }
//}