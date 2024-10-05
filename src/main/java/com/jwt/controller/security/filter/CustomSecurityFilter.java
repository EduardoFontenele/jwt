package com.jwt.controller.security.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@RequiredArgsConstructor
@Service
@Slf4j
public class CustomSecurityFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        final String authorizationHeader = request.getHeader("Authorization");

        if (authorizationHeader == null || authorizationHeader.isBlank()) {
            log.info("JWT not present - URL: {}, Method: {}, IP: {}, User-Agent: {}",
                    request.getRequestURI(), request.getMethod(),
                    request.getRemoteAddr(), request.getHeader("User-Agent"));
            filterChain.doFilter(request, response);
            return;
        }

        if (!authorizationHeader.startsWith("Bearer ")) {
            log.info("Invalid JWT - URL: {}, Method: {}, IP: {}, User-Agent: {}",
                    request.getRequestURI(), request.getMethod(),
                    request.getRemoteAddr(), request.getHeader("User-Agent"));
            filterChain.doFilter(request, response);
            return;
        }

        CharSequence charSequence = authorizationHeader.substring(7);

        try {
            Jwt<?, Claims> jwt = Jwts.parser()
                    .verifyWith(JwtRequestWrapper.secretKey)
                    .build()
                    .parseSignedClaims(charSequence);

            log.info(jwt.getPayload().toString());

        } catch (JwtException e) {
            throw new JwtException(e.getMessage());
        }


        filterChain.doFilter(request, response);
    }
}
