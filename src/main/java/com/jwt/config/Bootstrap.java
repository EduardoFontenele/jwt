package com.jwt.config;

import com.jwt.entity.RoleEntity;
import com.jwt.entity.UserEntity;
import com.jwt.repository.RoleRepository;
import com.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;

@Component
@RequiredArgsConstructor
public class Bootstrap implements CommandLineRunner {

    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        loadRoles();
        loadSuperUser();
    }

    private void loadSuperUser() {
        if (userRepository.count() == 0) {
            RoleEntity adminRole = roleRepository.findByName("ROLE_ADMIN")
                    .orElseThrow(() -> new NoSuchElementException("Role not found or not present"));

            RoleEntity userRole = roleRepository.findByName("ROLE_USER")
                    .orElseThrow(() -> new NoSuchElementException("Role not found or not present"));

            Set<RoleEntity> roles = new HashSet<>(2);
            roles.add(adminRole);
            roles.add(userRole);

            UserEntity user = UserEntity.builder()
                    .username("eduardo")
                    .password(passwordEncoder.encode("admin123"))
                    .roles(roles)
                    .build();

            userRepository.save(user);
        }
    }

    private void loadRoles() {
        if (roleRepository.count() == 0) {
            RoleEntity admin = new RoleEntity();
            admin.setName("ROLE_ADMIN");

            RoleEntity user = new RoleEntity();
            user.setName("ROLE_USER");

            roleRepository.saveAll(List.of(admin, user));
        }
    }
}
