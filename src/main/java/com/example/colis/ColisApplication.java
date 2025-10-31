package com.example.colis;

import com.example.colis.entity.User;
import com.example.colis.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class ColisApplication {

    public static void main(String[] args) {
        SpringApplication.run(ColisApplication.class, args);
    }


    @Bean
    CommandLineRunner initAdmin(UserRepository userRepository) {
        return args -> {
            if (userRepository.findByEmail("admin@amana.ma") == null) {
                User admin = new User();
                admin.setEmail("admin@amana.ma");
                admin.setPassword("admin123");
                admin.setFullName("Administrateur");
                admin.setRole("ADMIN");


                admin.setAccountNonExpired(true);
                admin.setAccountNonLocked(true);
                admin.setCredentialsNonExpired(true);
                admin.setEnabled(true);

                userRepository.save(admin);
                System.out.println("Compte admin créé avec succès");
            }
        };
    }

}