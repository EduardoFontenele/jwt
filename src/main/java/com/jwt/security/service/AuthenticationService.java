package com.jwt.security.service;

import com.jwt.security.model.UserRequestDTO;
import com.jwt.security.model.UserResponseDTO;
import com.jwt.security.model.UserSecurityDTO;
import com.jwt.security.persistence.Role;
import com.jwt.security.persistence.UserEntity;
import com.jwt.security.persistence.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.NoSuchElementException;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final CustomUserDetailsService customUserDetailsService;
    private final JwtService jwtService;

    public UserResponseDTO register(UserRequestDTO user) {
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

        return new UserResponseDTO(userEntity.getUsername(), jwtService.generateToken(userEntity.getUsername()));
    }

    public UserResponseDTO login(UserRequestDTO user) {
        UserDetails userSecurityDTO = customUserDetailsService.loadUserByUsername(user.username());
        if (!passwordEncoder.matches(user.password(), userSecurityDTO.getPassword())) throw new BadCredentialsException("Password is wrong");
        return new UserResponseDTO(userSecurityDTO.getUsername(), jwtService.generateToken(userSecurityDTO.getUsername()));
    }


}
