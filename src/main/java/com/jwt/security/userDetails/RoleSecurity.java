package com.jwt.security.userDetails;

import com.jwt.entity.RoleEntity;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

@RequiredArgsConstructor
public class RoleSecurity implements GrantedAuthority {
    private final RoleEntity role;

    @Override
    public String getAuthority() {
        return role.getName();
    }
}
