package com.jwt.security.service;

import com.jwt.entity.UserEntity;
import com.jwt.repository.UserRepository;
import com.jwt.security.userDetails.UserSecurity;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class ApiUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<UserEntity> foundUser = userRepository.findByUsername(username);

        return foundUser.map(UserSecurity::new)
                .orElseThrow(() -> new UsernameNotFoundException("User not found or not present"));
    }
}
