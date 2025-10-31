//package com.example.colis.ml;
//
//import org.springframework.stereotype.Service;
//
//import java.util.*;
//import java.util.stream.Collectors;
//
//
//@Service
//    public class RouteOptimizer {
//
//        private Map<String, Map<String, Integer>> graph;
//
//        public RouteOptimizer() {
//            initializeMoroccoGraph();
//        }
//
//        private void initializeMoroccoGraph() {
//            // Distances approximatives entre villes (km)
//            graph = Map.of(
//                    "Casablanca", Map.of("Rabat", 90, "Marrakech", 240),
//                    "Rabat", Map.of("Casablanca", 90, "Fes", 200),
//                    "Fes", Map.of("Rabat", 200, "Tanger", 300)
//
//            );
//        }
//
//        public List<String> optimizeRoute(String start, List<String> destinations) {
//            Map<String, Integer> distances = new HashMap<>();
//            PriorityQueue<String> queue = new PriorityQueue<>(Comparator.comparingInt(distances::get));
//
//            // Initialisation
//            graph.keySet().forEach(city -> distances.put(city, Integer.MAX_VALUE));
//            distances.put(start, 0);
//            queue.addAll(graph.keySet());
//
//            // Algorithme de Dijkstra
//            while (!queue.isEmpty()) {
//                String current = queue.poll();
//                for (Map.Entry<String, Integer> neighbor : graph.get(current).entrySet()) {
//                    int alt = distances.get(current) + neighbor.getValue();
//                    if (alt < distances.get(neighbor.getKey())) {
//                        distances.put(neighbor.getKey(), alt);
//                        // Mise à jour de la priorité
//                        queue.remove(neighbor.getKey());
//                        queue.add(neighbor.getKey());
//                    }
//                }
//            }
//
//            // Ordonner les destinations
//            return destinations.stream()
//                    .sorted(Comparator.comparingInt(distances::get))
//                    .collect(Collectors.toList());
//        }
//    }
//
