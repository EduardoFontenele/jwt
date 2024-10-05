package com.jwt.service;

import com.jwt.dto.AuthenticationDTO;
import com.jwt.dto.AuthenticationResponse;
import com.jwt.dto.RegisterDTO;
import com.jwt.entity.Role;
import com.jwt.entity.UserEntity;
import com.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.NoSuchElementException;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterDTO registerDTO) {
        var user = UserEntity.builder()
                .firstname(registerDTO.firstname())
                .lastname(registerDTO.lastname())
                .email(registerDTO.email())
                .password(passwordEncoder.encode(registerDTO.password()))
                .role(Role.USER)
                .build();

        userRepository.save(user);
        var jwtToken = jwtService.generateToken(user);
        return new AuthenticationResponse(jwtToken);
    }

    public AuthenticationResponse authenticate(AuthenticationDTO authenticationDTO) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authenticationDTO.email(), authenticationDTO.password()));

        var user =  userRepository.findByEmail(authenticationDTO.email())
                .orElseThrow(() -> new NoSuchElementException("User not found"));
        var jwtToken = jwtService.generateToken(user);

        return new AuthenticationResponse(jwtToken);
    }
}
