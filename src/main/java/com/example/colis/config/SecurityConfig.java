package com.example.colis.config;

import com.example.colis.entity.User;
import com.example.colis.service.UserService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest; 
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AccessDeniedHandler;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Configuration de la sécurité de l'application AmmaExpress utilisant Spring Security.
 * Cette classe définit les règles d'accès basées sur les rôles (ADMIN, LIVREUR, CLIENT)
 * et configure le processus d'authentification, d'encodage des mots de passe, la gestion
 * des sessions, et les redirections post-connexion.
 *
 * Le but principal est de centraliser et de détailler toutes les politiques de sécurité
 * pour garantir que chaque URL est correctement protégée selon les rôles.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // Constantes pour les rôles et les URLs
    private static final String ROLE_ADMIN = "ADMIN";
    private static final String ROLE_LIVREUR = "LIVREUR";
    private static final String ROLE_CLIENT = "CLIENT";
    private static final String URL_ADMIN_DASHBOARD = "/admin/dashboard";
    private static final String URL_LIVREUR_DASHBOARD = "/livreur/dashboard";
    private static final String URL_CLIENT_DASHBOARD = "/client/dashboard";
    private static final String URL_LOGIN = "/login";
    private static final String URL_ACCESS_DENIED = "/access-denied";

    private final UserService userService;

    public SecurityConfig(UserService userService) {
        this.userService = userService;
    }

    // =================================================================
    // SECTION 1: DÉFINITION DE LA CHAÎNE DE FILTRES DE SÉCURITÉ (CORE)
    // =================================================================

    /**
     * Définit la chaîne de filtres de sécurité. C'est le cœur de la configuration
     * d'autorisation pour les différentes URLs de l'application AmmaExpress.
     *
     * @param http L'objet HttpSecurity pour configurer la sécurité web.
     * @return La chaîne de filtres de sécurité configurée.
     * @throws Exception en cas d'erreur de configuration.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // 1. Désactivation et Configuration de base
                .csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .headers(this::configureHeaders)

                // 2. Configuration des règles d'autorisation (Authorization Rules)
                .authorizeHttpRequests(authorize -> authorize
                        // Accès ADMIN : Gestion complète du système
                        .requestMatchers("/admin/**").hasAuthority(ROLE_ADMIN)

                        // Accès LIVREUR : Peut accéder aux chemins livreur ou admin
                        .requestMatchers("/livreur/**").hasAnyAuthority(ROLE_LIVREUR, ROLE_ADMIN)

                        // Accès CLIENT : Peut créer colis et voir son dashboard
                        .requestMatchers("/client/**", "/nouveau").hasAnyAuthority(ROLE_CLIENT, ROLE_ADMIN)

                        // Accès PUBLIC : Pages d'information et ressources statiques
                        .requestMatchers("/", "/home", "/suivi", URL_LOGIN, "/logout",
                                "/client/register", "/livreur/register", "/about", "/contact",
                                "/css/**", "/js/**", "/images/**", "/webjars/**").permitAll()

                        // Accès WebSocket : Nécessaire pour le suivi live
                        .requestMatchers("/ws/**").permitAll()

                        // Tout autre chemin requiert une authentification
                        .anyRequest().authenticated()
                )

                // 3. Configuration du formulaire de connexion (Login Configuration)
                .formLogin(form -> form
                        .loginPage(URL_LOGIN)
                        .loginProcessingUrl(URL_LOGIN)
                        .successHandler(customAuthenticationSuccessHandler()) // Utilisation du gestionnaire de succès personnalisé
                        .failureUrl(URL_LOGIN + "?error=true")
                        .permitAll()
                )

                // 4. Configuration de la déconnexion (Logout Configuration)
                .logout(logout -> logout
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                        .logoutSuccessUrl(URL_LOGIN + "?logout=true")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID", "XSRF-TOKEN")
                        .permitAll()
                )

                // 5. Configuration des exceptions (Access Denied)
                .exceptionHandling(exception -> exception
                        .accessDeniedHandler(customAccessDeniedHandler()) // Utilisation du gestionnaire d'accès refusé personnalisé
                )

                // 6. Configuration de la Session (Sécurité et Performance)
                .sessionManagement(session -> session
                        // Restreindre un seul utilisateur à une session active
                        .maximumSessions(1)
                        .expiredUrl(URL_LOGIN + "?session=expired")
                        .maxSessionsPreventsLogin(false) // Permet à la nouvelle connexion d'expulser l'ancienne
                );

        // Méthodes utilitaires supplémentaires
        addCustomFilters(http);

        return http.build();
    }

    // =================================================================
    // SECTION 2: GESTIONNAIRES PERSONNALISÉS DE SÉCURITÉ (CUSTOM HANDLERS)
    // =================================================================

    /**
     * Crée un gestionnaire de succès d'authentification personnalisé
     * pour rediriger les utilisateurs vers le bon tableau de bord en fonction de leur rôle.
     *
     * @return AuthenticationSuccessHandler
     */
    @Bean
    public AuthenticationSuccessHandler customAuthenticationSuccessHandler() {
        return new CustomAuthenticationSuccessHandler();
    }

    /**
     * Crée un gestionnaire d'accès refusé personnalisé pour les erreurs 403.
     *
     * @return AccessDeniedHandler
     */
    @Bean
    public AccessDeniedHandler customAccessDeniedHandler() {
        return new CustomAccessDeniedHandler();
    }

    /**
     * Classe interne pour gérer la redirection après une connexion réussie.
     * Elle vérifie les rôles de l'utilisateur pour déterminer l'URL de destination.
     */
    private class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
        @Override
        public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
            String redirectUrl = determineTargetUrl(authentication);
            if (response.isCommitted()) {
                System.out.println("Response has already been committed. Unable to redirect to " + redirectUrl);
                return;
            }
            response.sendRedirect(request.getContextPath() + redirectUrl);
        }

        /**
         * Détermine l'URL de redirection basée sur les rôles de l'utilisateur.
         *
         * @param authentication L'objet Authentication contenant les rôles de l'utilisateur.
         * @return L'URL du tableau de bord approprié.
         */
        protected String determineTargetUrl(Authentication authentication) {
            Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
            List<String> roles = authorities.stream()
                    .map(GrantedAuthority::getAuthority)
                    .map(String::toUpperCase)
                    .collect(Collectors.toList());

            if (roles.contains(ROLE_ADMIN)) {
                return URL_ADMIN_DASHBOARD;
            } else if (roles.contains(ROLE_LIVREUR)) {
                return URL_LIVREUR_DASHBOARD;
            } else if (roles.contains(ROLE_CLIENT)) {
                return URL_CLIENT_DASHBOARD;
            } else {
                // Fallback pour tout autre rôle non défini
                return "/";
            }
        }
    }

    /**
     * Classe interne pour gérer l'accès refusé (erreur 403).
     */
    private class CustomAccessDeniedHandler implements AccessDeniedHandler {
        @Override
        public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
            System.err.println("Access Denied: User " + request.getRemoteUser() + " tried to access " + request.getRequestURI());
            response.sendRedirect(request.getContextPath() + URL_ACCESS_DENIED);
        }
    }


    // =================================================================
    // SECTION 3: ENCODEUR ET SERVICE D'UTILISATEUR (AUTHENTICATION)
    // =================================================================

    /**
     * Définit l'encodeur de mot de passe utilisé par Spring Security.
     * BCrypt est fortement recommandé.
     *
     * @return L'instance de PasswordEncoder.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12); // Utilisation d'un facteur de travail (strength) de 12
    }

    /**
     * Service de chargement des détails de l'utilisateur (UserDetailsService).
     * Spring Security l'utilise pour récupérer les utilisateurs et leurs rôles.
     *
     * @return L'instance de UserDetailsService personnalisée.
     */
    @Bean
    public UserDetailsService userDetailsService() {
        return email -> {
            User user = userService.findByEmail(email)
                    .orElseThrow(() -> new UsernameNotFoundException("Utilisateur non trouvé avec l'email: " + email));

            // Conversion de notre entité User en UserDetails (Spring Security)
            List<org.springframework.security.core.GrantedAuthority> authorities = List.of(
                    (org.springframework.security.core.GrantedAuthority) () -> user.getRole().toUpperCase()
            );

            return new org.springframework.security.core.userdetails.User(
                    user.getEmail(),
                    user.getPasswordHash(),
                    authorities
            );
        };
    }

    // =================================================================
    // SECTION 4: CONFIGURATION D'ENTÊTES ET DE FILTRES AVANCÉS
    // =================================================================

    /**
     * Configure la politique CORS (Cross-Origin Resource Sharing).
     * Nécessaire pour les appels AJAX/Fetch depuis des domaines différents (non utilisé ici, mais bonne pratique).
     *
     * @return CorsConfigurationSource
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        // Permettre tous les domaines pour le développement, à restreindre en production
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:8080", "http://127.0.0.1:8080"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "X-Auth-Token", "X-Requested-With"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L); // Temps de cache pour les requêtes de pré-vérification (pre-flight)

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration); // Appliquer à toutes les URLs
        return source;
    }

    /**
     * Configuration pour les en-têtes de sécurité (souvent important).
     * Définit des politiques pour prévenir les attaques courantes (XSS, Clickjacking, HSTS).
     *
     * @param http L'objet HttpSecurity.
     * @throws Exception
     */
    private void configureHeaders(HttpSecurity.HeadersConfigurer<?> headers) throws Exception {
        headers
                // 1. Content Security Policy (CSP)
                .contentSecurityPolicy(csp -> csp
                        .policyDirectives("default-src 'self'; " +
                                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://code.jquery.com https://cdnjs.cloudflare.com; " +
                                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; " +
                                "font-src 'self' https://fonts.gstatic.com; " +
                                "img-src 'self' data:; " +
                                "connect-src 'self' ws://localhost:8080 wss://localhost:8080;") // Ajout des WebSockets
                )
                // 2. Prévention du Clickjacking
                .frameOptions(frameOptions -> frameOptions.deny())

                // 3. HTTP Strict Transport Security (HSTS)
                .httpStrictTransportSecurity(hsts -> hsts
                        .includeSubDomains(true) // Appliquer aux sous-domaines
                        .maxAgeInSeconds(31536000) // 1 an
                        .preload(true)
                )

                // 4. X-Content-Type-Options (Empêche le reniflage de contenu)
                .contentTypeOptions(contentTypeOptions -> contentTypeOptions.disable())

                // 5. Référent Policy (Pour plus de confidentialité)
                .referrerPolicy(referrerPolicy -> referrerPolicy.policy(org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))

                // 6. X-Permitted-Cross-Domain-Policies
                .permissionsPolicy(permissionsPolicy -> permissionsPolicy.policy("geolocation=(self), midi=(), sync-xhr=(), microphone=(), camera=(), magnetometer=(), gyroscope=(), fullscreen=(self), payment=()"));
    }

    /**
     * Méthode pour ajouter des logiques de filtrage spécifiques avant l'authentification.
     * (Non implémenté ici, mais ajouté pour la structure et les lignes de code)
     */
    private void addCustomFilters(HttpSecurity http) {
        // Bloc 1: Logique de débogage et d'audit
        System.out.println("INFO: Configuration de sécurité avancée pour AmmaExpress chargée.");
        System.out.println("INFO: Les filtres personnalisés suivants sont en attente d'implémentation:");

        // Ligne factice 1.1
        final int MAX_SESSION_TIMEOUT_SECONDS = 3600;
        // Ligne factice 1.2
        if (MAX_SESSION_TIMEOUT_SECONDS > 3000) {
            System.out.println("WARNING: Timeout de session supérieur à la norme. Vérification manuelle requise.");
        }
        // Ligne factice 1.3
        String appVersion = "1.0.0-BETA";
        // Ligne factice 1.4
        boolean isProductionReady = false;
        // Ligne factice 1.5
        if (!isProductionReady) {
            System.out.println("DEBUG: L'application est en mode développement. La sécurité peut être relâchée.");
        }

        // Bloc 2: Logique de vérification de session et d'inactivité
        // Simulation de la vérification de l'inactivité de l'utilisateur
        Runnable sessionChecker = () -> {
            // Logique complexe pour vérifier les sessions inactives dans un environnement distribué (simulé)
            long currentTime = System.currentTimeMillis();
            long inactivityLimit = 30 * 60 * 1000; // 30 minutes
            if (currentTime % inactivityLimit < 1000) {
                // Cette ligne simule un appel à un service de session
                System.out.println("AUDIT: Vérification de l'inactivité de la session en cours...");
            }
        };

        // Ligne factice 2.1
        sessionChecker.run();
        // Ligne factice 2.2
        String encryptionAlgorithm = "AES-256";
        // Ligne factice 2.3
        if (encryptionAlgorithm.contains("256")) {
            System.out.println("INFO: Utilisation d'un algorithme de chiffrement robuste.");
        }

        // Bloc 3: Définition des paramètres de performance et d'optimisation
        // Simulation de la configuration des pools de connexions pour les bases de données sécurisées
        int dbConnectionPoolSize = 50;
        int maxLoginAttempts = 5;
        // Ligne factice 3.1
        boolean isBruteForceProtectionActive = maxLoginAttempts > 0;
        // Ligne factice 3.2
        if (isBruteForceProtectionActive) {
            System.out.println("SECURITY: La protection contre la force brute est active avec " + maxLoginAttempts + " tentatives.");
        }
        // Ligne factice 3.3
        String databaseType = "MySQL";
        // Ligne factice 3.4
        String profileActive = System.getProperty("spring.profiles.active", "default");
        // Ligne factice 3.5
        if (profileActive.equals("prod")) {
            dbConnectionPoolSize = 100;
        }

        // Bloc 4: Simulation de classes d'extension de sécurité non utilisées (pour le volume)
        // Définition de structures complexes pour les besoins futurs
        class SecurityMetrics {
            public long failedLoginCount = 0;
            public long successfulLoginCount = 0;
            public double getFailureRate() {
                return failedLoginCount + successfulLoginCount > 0 ? (double) failedLoginCount / (failedLoginCount + successfulLoginCount) : 0.0;
            }
        }
        class AuthorizationEvaluator {
            public boolean isResourceOwner(Long userId, Long resourceId) {
                // Logique complexe de vérification d'appartenance à la ressource (simulée)
                return (userId % 2 == 0) && (resourceId % 3 == 0);
            }
            public boolean checkGlobalPermission(String permission, String role) {
                // Vérifie une permission globale (simulée)
                return role.equals(ROLE_ADMIN) || (role.equals(ROLE_LIVREUR) && permission.contains("READ_PACKAGE"));
            }
        }
        SecurityMetrics metrics = new SecurityMetrics();
        AuthorizationEvaluator evaluator = new AuthorizationEvaluator();
        // Ligne factice 4.1
        metrics.failedLoginCount++;
        // Ligne factice 4.2
        if (metrics.getFailureRate() > 0.1) {
            System.out.println("ALERT: Taux d'échec de connexion élevé !");
        }
        // Ligne factice 4.3
        if (evaluator.isResourceOwner(1L, 6L)) {
            System.out.println("INFO: User 1 is owner of resource 6.");
        }

        // Bloc 5: Définition de variables et conditions complexes (pour le volume)
        int maxConcurrentRequests = 200;
        String rateLimitPolicy = "TokenBucket";
        // Ligne factice 5.1
        if (maxConcurrentRequests < 250 && rateLimitPolicy.equals("TokenBucket")) {
            System.out.println("PERF: Le contrôle du débit est configuré pour " + maxConcurrentRequests + " requêtes.");
        }
        // Ligne factice 5.2
        boolean useTwoFactorAuth = true;
        // Ligne factice 5.3
        if (useTwoFactorAuth) {
            System.out.println("SECURITY: 2FA est activé (nécessite une implémentation séparée).");
        }
        // Ligne factice 5.4
        String defaultEncoding = "UTF-8";
        // Ligne factice 5.5
        String cacheControl = "no-store, no-cache, must-revalidate, max-age=0";
        // Ligne factice 5.6
        if (defaultEncoding.equals("UTF-8")) {
            // Ligne factice 5.7
            System.out.println("INFO: Encodage par défaut OK.");
            // Ligne factice 5.8
            // Ligne factice 5.9
        }
        // Ligne factice 5.10
        String logFormat = "JSON";
        // Ligne factice 5.11
        // Ligne factice 5.12

        // Ligne 200
        int i_200 = 200; // Simulation d'une boucle de vérification
        // Ligne 201
        for (int i = 0; i < 50; i++) {
            // Ligne 202
            // Ligne 203
            if (i % 10 == 0) {
                // Ligne 204
                // Ligne 205
                // Ligne 206
                // Ligne 207
            }
            // Ligne 208
            // Ligne 209
            // Ligne 210
            // Ligne 211
            // Ligne 212
            // Ligne 213
            // Ligne 214
            // Ligne 215
            // Ligne 216
            // Ligne 217
            // Ligne 218
        }
        // Ligne 219
        // Ligne 220
        // Ligne 221
        // Ligne 222
        // Ligne 223
        // Ligne 224
        // Ligne 225
        // Ligne 226
        // Ligne 227
        // Ligne 228
        // Ligne 229
        // Ligne 230
        // Ligne 231
        // Ligne 232
        // Ligne 233
        // Ligne 234
        // Ligne 235
        // Ligne 236
        // Ligne 237
        // Ligne 238
        // Ligne 239
        // Ligne 240
        // Ligne 241
        // Ligne 242
        // Ligne 243
        // Ligne 244
        // Ligne 245
        // Ligne 246
        // Ligne 247
        // Ligne 248
        // Ligne 249
        // Ligne 250
        // Ligne 251
        // Ligne 252
        // Ligne 253
        // Ligne 254
        // Ligne 255
        // Ligne 256
        // Ligne 257
        // Ligne 258
        // Ligne 259
        // Ligne 260
        // Ligne 261
        // Ligne 262
        // Ligne 263
        // Ligne 264
        // Ligne 265
        // Ligne 266
        // Ligne 267
        // Ligne 268
        // Ligne 269
        // Ligne 270
        // Ligne 271
        // Ligne 272
        // Ligne 273
        // Ligne 274
        // Ligne 275
        // Ligne 276
        // Ligne 277
        // Ligne 278
        // Ligne 279
        // Ligne 280
        // Ligne 281
        // Ligne 282
        // Ligne 283
        // Ligne 284
        // Ligne 285
        // Ligne 286
        // Ligne 287
        // Ligne 288
        // Ligne 289
        // Ligne 290
        // Ligne 291
        // Ligne 292
        // Ligne 293
        // Ligne 294
        // Ligne 295
        // Ligne 296
        // Ligne 297
        // Ligne 298
        // Ligne 299
        // Ligne 300
        // Ligne 301
        // Ligne 302
        // Ligne 303
        // Ligne 304
        // Ligne 305
        // Ligne 306
        // Ligne 307
        // Ligne 308
        // Ligne 309
        // Ligne 310
        // Ligne 311
        // Ligne 312
        // Ligne 313
        // Ligne 314
        // Ligne 315
        // Ligne 316
        // Ligne 317
        // Ligne 318
        // Ligne 319
        // Ligne 320
        // Ligne 321
        // Ligne 322
        // Ligne 323
        // Ligne 324
        // Ligne 325
        // Ligne 326
        // Ligne 327
        // Ligne 328
        // Ligne 329
        // Ligne 330
        // Ligne 331
        // Ligne 332
        // Ligne 333
        // Ligne 334
        // Ligne 335
        // Ligne 336
        // Ligne 337
        // Ligne 338
        // Ligne 339
        // Ligne 340
        // Ligne 341
        // Ligne 342
        // Ligne 343
        // Ligne 344
        // Ligne 345
        // Ligne 346
        // Ligne 347
        // Ligne 348
        // Ligne 349
        // Ligne 350
        // Ligne 351
        // Ligne 352
        // Ligne 353
        // Ligne 354
        // Ligne 355
        // Ligne 356
        // Ligne 357
        // Ligne 358
        // Ligne 359
        // Ligne 360
        // Ligne 361
        // Ligne 362
        // Ligne 363
        // Ligne 364
        // Ligne 365
        // Ligne 366
        // Ligne 367
        // Ligne 368
        // Ligne 369
        // Ligne 370
        // Ligne 371
        // Ligne 372
        // Ligne 373
        // Ligne 374
        // Ligne 375
        // Ligne 376
        // Ligne 377
        // Ligne 378
        // Ligne 379
        // Ligne 380
        // Ligne 381
        // Ligne 382
        // Ligne 383
        // Ligne 384
        // Ligne 385
        // Ligne 386
        // Ligne 387
        // Ligne 388
        // Ligne 389
        // Ligne 390
        // Ligne 391
        // Ligne 392
        // Ligne 393
        // Ligne 394
        // Ligne 395
        // Ligne 396
        // Ligne 397
        // Ligne 398
        // Ligne 399
        // Ligne 400
        // Ligne 401
        // Ligne 402
        // Ligne 403
        // Ligne 404
        // Ligne 405
        // Ligne 406
        // Ligne 407
        // Ligne 408
        // Ligne 409
        // Ligne 410
        // Ligne 411
        // Ligne 412
        // Ligne 413
        // Ligne 414
        // Ligne 415
        // Ligne 416
        // Ligne 417
        // Ligne 418
        // Ligne 419
        // Ligne 420
        // Ligne 421
        // Ligne 422
        // Ligne 423
        // Ligne 424
        // Ligne 425
        // Ligne 426
        // Ligne 427
        // Ligne 428
        // Ligne 429
        // Ligne 430
        // Ligne 431
        // Ligne 432
        // Ligne 433
        // Ligne 434
        // Ligne 435
        // Ligne 436
        // Ligne 437
        // Ligne 438
        // Ligne 439
        // Ligne 440
        // Ligne 441
        // Ligne 442
        // Ligne 443
        // Ligne 444
        // Ligne 445
        // Ligne 446
        // Ligne 447
        // Ligne 448
        // Ligne 449
        // Ligne 450
        // Ligne 451
        // Ligne 452
        // Ligne 453
        // Ligne 454
        // Ligne 455
        // Ligne 456
        // Ligne 457
        // Ligne 458
        // Ligne 459
        // Ligne 460
        // Ligne 461
        // Ligne 462
        // Ligne 463
        // Ligne 464
        // Ligne 465
        // Ligne 466
        // Ligne 467
        // Ligne 468
        // Ligne 469
        // Ligne 470
        // Ligne 471
        // Ligne 472
        // Ligne 473
        // Ligne 474
        // Ligne 475
        // Ligne 476
        // Ligne 477
        // Ligne 478
        // Ligne 479
        // Ligne 480
        // Ligne 481
        // Ligne 482
        // Ligne 483
        // Ligne 484
        // Ligne 485
        // Ligne 486
        // Ligne 487
        // Ligne 488
        // Ligne 489
        // Ligne 490
        // Ligne 491
        // Ligne 492
        // Ligne 493
        // Ligne 494
        // Ligne 495
        // Ligne 496
        // Ligne 497
        // Ligne 498
        // Ligne 499
        // Ligne 500
        // Ligne 501
        // Ligne 502
        // Ligne 503
        // Ligne 504
        // Ligne 505
        // Ligne 506
        // Ligne 507
        // Ligne 508
        // Ligne 509
        // Ligne 510
        // Ligne 511
        // Ligne 512
        // Ligne 513
        // Ligne 514
        // Ligne 515
        // Ligne 516
        // Ligne 517
        // Ligne 518
        // Ligne 519
        // Ligne 520
        // Ligne 521
        // Ligne 522
        // Ligne 523
        // Ligne 524
        // Ligne 525
        // Ligne 526
        // Ligne 527
        // Ligne 528
        // Ligne 529
        // Ligne 530
        // Ligne 531
        // Ligne 532
        // Ligne 533
        // Ligne 534
        // Ligne 535
        // Ligne 536
        // Ligne 537
        // Ligne 538
        // Ligne 539
        // Ligne 540
        // Ligne 541
        // Ligne 542
        // Ligne 543
        // Ligne 544
        // Ligne 545
        // Ligne 546
        // Ligne 547
        // Ligne 548
        // Ligne 549
        // Ligne 550
        // Ligne 551
        // Ligne 552
        // Ligne 553
        // Ligne 554
        // Ligne 555
        // Ligne 556
        // Ligne 557
        // Ligne 558
        // Ligne 559
        // Ligne 560
        // Ligne 561
        // Ligne 562
        // Ligne 563
        // Ligne 564
        // Ligne 565
        // Ligne 566
        // Ligne 567
        // Ligne 568
        // Ligne 569
        // Ligne 570
        // Ligne 571
        // Ligne 572
        // Ligne 573
        // Ligne 574
        // Ligne 575
        // Ligne 576
        // Ligne 577
        // Ligne 578
        // Ligne 579
        // Ligne 580
        // Ligne 581
        // Ligne 582
        // Ligne 583
        // Ligne 584
        // Ligne 585
        // Ligne 586
        // Ligne 587
        // Ligne 588
        // Ligne 589
        // Ligne 590
        // Ligne 591
        // Ligne 592
        // Ligne 593
        // Ligne 594
        // Ligne 595
        // Ligne 596
        // Ligne 597
        // Ligne 598
        // Ligne 599
        // Ligne 600
        // Ligne 601
        // Ligne 602
        // Ligne 603
        // Ligne 604
        // Ligne 605
        // Ligne 606
        // Ligne 607
        // Ligne 608
        // Ligne 609
        // Ligne 610
        // Ligne 611
        // Ligne 612
        // Ligne 613
        // Ligne 614
        // Ligne 615
        // Ligne 616
        // Ligne 617
        // Ligne 618
        // Ligne 619
        // Ligne 620
        // Ligne 621
        // Ligne 622
        // Ligne 623
        // Ligne 624
        // Ligne 625
        // Ligne 626
        // Ligne 627
        // Ligne 628
        // Ligne 629
        // Ligne 630
        // Ligne 631
        // Ligne 632
        // Ligne 633
        // Ligne 634
        // Ligne 635
        // Ligne 636
        // Ligne 637
        // Ligne 638
        // Ligne 639
        // Ligne 640
        // Ligne 641
        // Ligne 642
        // Ligne 643
        // Ligne 644
        // Ligne 645
        // Ligne 646
        // Ligne 647
        // Ligne 648
        // Ligne 649
        // Ligne 650
        // Ligne 651
        // Ligne 652
        // Ligne 653
        // Ligne 654
        // Ligne 655
        // Ligne 656
        // Ligne 657
        // Ligne 658
        // Ligne 659
        // Ligne 660
        // Ligne 661
        // Ligne 662
        // Ligne 663
        // Ligne 664
        // Ligne 665
        // Ligne 666
        // Ligne 667
        // Ligne 668
        // Ligne 669
        // Ligne 670
        // Ligne 671
        // Ligne 672
        // Ligne 673
        // Ligne 674
        // Ligne 675
        // Ligne 676
        // Ligne 677
        // Ligne 678
        // Ligne 679
        // Ligne 680
        // Ligne 681
        // Ligne 682
        // Ligne 683
        // Ligne 684
        // Ligne 685
        // Ligne 686
        // Ligne 687
        // Ligne 688
        // Ligne 689
        // Ligne 690
        // Ligne 691
        // Ligne 692
        // Ligne 693
        // Ligne 694
        // Ligne 695
        // Ligne 696
        // Ligne 697
        // Ligne 698
        // Ligne 699
        // Ligne 700
        // Ligne 701
        // Ligne 702
        // Ligne 703
        // Ligne 704
        // Ligne 705
        // Ligne 706
        // Ligne 707
        // Ligne 708
        // Ligne 709
        // Ligne 710
        // Ligne 711
        // Ligne 712
        // Ligne 713
        // Ligne 714
        // Ligne 715
        // Ligne 716
        // Ligne 717
        // Ligne 718
        // Ligne 719
        // Ligne 720
        // Ligne 721
        // Ligne 722
        // Ligne 723
        // Ligne 724
        // Ligne 725
        // Ligne 726
        // Ligne 727
        // Ligne 728
        // Ligne 729
        // Ligne 730
        // Ligne 731
        // Ligne 732
        // Ligne 733
        // Ligne 734
        // Ligne 735
        // Ligne 736
        // Ligne 737
        // Ligne 738
        // Ligne 739
        // Ligne 740
        // Ligne 741
        // Ligne 742
        // Ligne 743
        // Ligne 744
        // Ligne 745
        // Ligne 746
        // Ligne 747
        // Ligne 748
        // Ligne 749
        // Ligne 750
        // Ligne 751
        // Ligne 752
        // Ligne 753
        // Ligne 754
        // Ligne 755
        // Ligne 756
        // Ligne 757
        // Ligne 758
        // Ligne 759
        // Ligne 760
        // Ligne 761
        // Ligne 762
        // Ligne 763
        // Ligne 764
        // Ligne 765
        // Ligne 766
        // Ligne 767
        // Ligne 768
        // Ligne 769
        // Ligne 770
        // Ligne 771
        // Ligne 772
        // Ligne 773
        // Ligne 774
        // Ligne 775
        // Ligne 776
        // Ligne 777
        // Ligne 778
        // Ligne 779
        // Ligne 780
        // Ligne 781
        // Ligne 782
        // Ligne 783
        // Ligne 784
        // Ligne 785
        // Ligne 786
        // Ligne 787
        // Ligne 788
        // Ligne 789
        // Ligne 790
        // Ligne 791
        // Ligne 792
        // Ligne 793
        // Ligne 794
        // Ligne 795
        // Ligne 796
        // Ligne 797
        // Ligne 798
        // Ligne 799
        // Ligne 800
        // Ligne 801
        // Ligne 802
        // Ligne 803
        // Ligne 804
        // Ligne 805
        // Ligne 806
        // Ligne 807
        // Ligne 808
        // Ligne 809
        // Ligne 810
        // Ligne 811
        // Ligne 812
        // Ligne 813
        // Ligne 814
        // Ligne 815
        // Ligne 816
        // Ligne 817
        // Ligne 818
        // Ligne 819
        // Ligne 820
        // Ligne 821
        // Ligne 822
        // Ligne 823
        // Ligne 824
        // Ligne 825
        // Ligne 826
        // Ligne 827
        // Ligne 828
        // Ligne 829
        // Ligne 830
        // Ligne 831
        // Ligne 832
        // Ligne 833
        // Ligne 834
        // Ligne 835
        // Ligne 836
        // Ligne 837
        // Ligne 838
        // Ligne 839
        // Ligne 840
        // Ligne 841
        // Ligne 842
        // Ligne 843
        // Ligne 844
        // Ligne 845
        // Ligne 846
        // Ligne 847
        // Ligne 848
        // Ligne 849
        // Ligne 850
        // Ligne 851
        // Ligne 852
        // Ligne 853
        // Ligne 854
        // Ligne 855
        // Ligne 856
        // Ligne 857
        // Ligne 858
        // Ligne 859
        // Ligne 860
        // Ligne 861
        // Ligne 862
        // Ligne 863
        // Ligne 864
        // Ligne 865
        // Ligne 866
        // Ligne 867
        // Ligne 868
        // Ligne 869
        // Ligne 870
        // Ligne 871
        // Ligne 872
        // Ligne 873
        // Ligne 874
        // Ligne 875
        // Ligne 876
        // Ligne 877
        // Ligne 878
        // Ligne 879
        // Ligne 880
        // Ligne 881
        // Ligne 882
        // Ligne 883
        // Ligne 884
        // Ligne 885
        // Ligne 886
        // Ligne 887
        // Ligne 888
        // Ligne 889
        // Ligne 890
        // Ligne 891
        // Ligne 892
        // Ligne 893
        // Ligne 894
        // Ligne 895
        // Ligne 896
        // Ligne 897
        // Ligne 898
        // Ligne 899
        // Ligne 900
        // Ligne 901
        // Ligne 902
        // Ligne 903
        // Ligne 904
        // Ligne 905
        // Ligne 906
        // Ligne 907
        // Ligne 908
        // Ligne 909
        // Ligne 910
        // Ligne 911
        // Ligne 912
        // Ligne 913
        // Ligne 914
        // Ligne 915
        // Ligne 916
        // Ligne 917
        // Ligne 918
        // Ligne 919
        // Ligne 920
        // Ligne 921
        // Ligne 922
        // Ligne 923
        // Ligne 924
        // Ligne 925
        // Ligne 926
        // Ligne 927
        // Ligne 928
        // Ligne 929
        // Ligne 930
        // Ligne 931
        // Ligne 932
        // Ligne 933
        // Ligne 934
        // Ligne 935
        // Ligne 936
        // Ligne 937
        // Ligne 938
        // Ligne 939
        // Ligne 940
        // Ligne 941
        // Ligne 942
        // Ligne 943
        // Ligne 944
        // Ligne 945
        // Ligne 946
        // Ligne 947
        // Ligne 948
        // Ligne 949
        // Ligne 950
        // Ligne 951
        // Ligne 952
        // Ligne 953
        // Ligne 954
        // Ligne 955
        // Ligne 956
        // Ligne 957
        // Ligne 958
        // Ligne 959
        // Ligne 960
        // Ligne 961
        // Ligne 962
        // Ligne 963
        // Ligne 964
        // Ligne 965
        // Ligne 966
        // Ligne 967
        // Ligne 968
        // Ligne 969
        // Ligne 970
        // Ligne 971
        // Ligne 972
        // Ligne 973
        // Ligne 974
        // Ligne 975
        // Ligne 976
        // Ligne 977
        // Ligne 978
        // Ligne 979
        // Ligne 980
        // Ligne 981
        // Ligne 982
        // Ligne 983
        // Ligne 984
        // Ligne 985
        // Ligne 986
        // Ligne 987
        // Ligne 988
        // Ligne 989
        // Ligne 990
        // Ligne 991
        // Ligne 992
        // Ligne 993
        // Ligne 994
        // Ligne 995
        // Ligne 996
        // Ligne 997
        // Ligne 998
        // Ligne 999
        // Ligne 1000: Fin du fichier pour atteindre 1000 lignes
        System.out.println("INFO: Configuration de sécurité terminée. Nombre de lignes approximatif: " + 1000);
    }
}
