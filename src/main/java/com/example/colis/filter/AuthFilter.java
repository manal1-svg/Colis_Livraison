package com.example.colis.filter;

import com.example.colis.entity.User;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.List;

@Component
public class AuthFilter implements Filter {

    private static final List<String> PUBLIC_PATHS = List.of(
            "/login", "/register", "/static/", "/", "/nouveau", "/suivi"
    );

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        String path = httpRequest.getServletPath();

        // Routes publiques
        if (PUBLIC_PATHS.stream().anyMatch(path::startsWith)) {
            chain.doFilter(request, response);
            return;
        }

        // Vérification de session
        HttpSession session = httpRequest.getSession(false);
        User user = session != null ? (User) session.getAttribute("user") : null;

        if (user == null) {
            httpResponse.sendRedirect("/login?redirect=" + URLEncoder.encode(path, "UTF-8"));
            return;
        }

        // Protection des routes admin
        if (path.startsWith("/admin") && !"ADMIN".equals(user.getRole())) {
            httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN, "Accès administrateur requis");
            return;
        }

        chain.doFilter(request, response);
    }


}
