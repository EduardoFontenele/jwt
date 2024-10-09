package com.jwt.security.service;

import com.jwt.security.model.UserSecurityDTO;
import com.jwt.security.persistence.UserEntity;
import com.jwt.security.persistence.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<UserEntity> userOptional = userRepository.findByUsername(username);
        return userOptional.map(UserSecurityDTO::new)
                .orElseThrow(() -> new BadCredentialsException("User not present"));
    }
}
