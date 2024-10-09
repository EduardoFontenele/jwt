package com.jwt.security.service;

import com.jwt.security.model.RegisterUserRequest;
import com.jwt.security.model.RegisterUserResponse;
import com.jwt.security.persistence.Role;
import com.jwt.security.persistence.UserEntity;
import com.jwt.security.persistence.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public RegisterUserResponse register(RegisterUserRequest user) {
        if (userRepository.findByUsername(user.username()).isPresent()) {
            throw new AuthenticationException("User already exists") {
                @Override
                public String getMessage() {
                    return super.getMessage();
                }
            };
        }

        UserEntity userEntity = UserEntity.builder()
                .username(user.username())
                .password(passwordEncoder.encode(user.password()))
                .roles(Set.of(Role.ROLE_ADMIN))
                .build();
        userRepository.save(userEntity);

        return new RegisterUserResponse(userEntity.getUsername(), jwtService.generateToken(userEntity.getUsername()));
    }
}
