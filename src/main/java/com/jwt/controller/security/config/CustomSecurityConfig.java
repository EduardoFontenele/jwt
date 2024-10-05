package com.jwt.controller.security.config;

import com.jwt.controller.security.filter.CustomSecurityFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@RequiredArgsConstructor
public class CustomSecurityConfig {

    private final CustomSecurityFilter customSecurityFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .authorizeHttpRequests(request -> {
                    request.requestMatchers("/api/v1/authenticate/**").permitAll();
                    request.anyRequest().authenticated();
                })
                .csrf(AbstractHttpConfigurer::disable)
                .cors(AbstractHttpConfigurer::disable)
                .addFilterBefore(customSecurityFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }
}
