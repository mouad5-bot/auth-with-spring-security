package com.youcode.security.service;

import com.youcode.security.entities.Role;

import java.util.Optional;

public interface RoleService {
    Optional<Role> findByName(String roleUser);

    Role save(Role role);
}
