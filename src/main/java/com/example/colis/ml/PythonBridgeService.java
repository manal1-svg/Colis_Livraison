//package com.example.colis.ml;
//
//import org.springframework.stereotype.Service;
//
//import java.io.IOException;
//import java.nio.charset.StandardCharsets;
//import java.util.ArrayList;
//import java.util.Arrays;
//import java.util.List;
//import java.util.stream.Collectors;
//
//    @Service
//    public class PythonBridgeService {
//        private final String pythonExecutable = "python";
//        private final String scriptPath = "src/main/resources/python/address_model.py";
//
//        public List<Double> getRecommendations(String query, List<String> addresses) {
//            try {
//                List<String> command = new ArrayList<>();
//                command.add(pythonExecutable);
//                command.add(scriptPath);
//                command.add("recommend");
//                command.add(query);
//                command.addAll(addresses);
//
//                ProcessBuilder pb = new ProcessBuilder(command);
//                pb.redirectErrorStream(true);
//                Process process = pb.start();
//
//                String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
//                return Arrays.stream(output.split(","))
//                        .map(Double::parseDouble)
//                        .collect(Collectors.toList());
//
//            } catch (IOException e) {
//                throw new RuntimeException("Python execution failed", e);
//            }
//        }
//    }
//
