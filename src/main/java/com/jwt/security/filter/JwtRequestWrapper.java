package com.jwt.security.filter;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.SecretKey;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Slf4j
public class JwtRequestWrapper extends HttpServletRequestWrapper {
    private static final String secret = "8740d5ae463bba0ae63954665dbe54ecfc9faccdeb8920372b3d6f1b2cf009ec";
    public static final SecretKey secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));

    public String generateToken() {
        return Jwts.builder()
                .subject("Monique Elen")
                .issuer("127.0.0.1:8080")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 24))
                .signWith(secretKey)
                .compact();
    }


    public JwtRequestWrapper(HttpServletRequest request) throws UnsupportedEncodingException {
        super(request);
    }

    @Override
    public String getHeader(String name) {
        String token;

        try {
            token = generateToken();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        if ("Authorization".equals(name)) {
            return token;
        }
        return super.getHeader(name);
    }
}
