package com.youcode.security.service.impl;

import com.youcode.security.entities.Role;
import com.youcode.security.repository.RoleRepository;
import com.youcode.security.service.RoleService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class RoleServiceImpl implements RoleService {

    private final RoleRepository roleRpository;
    @Override
    public Optional<Role> findByName(String role) {
        return roleRpository.findByName(role);
    }

    @Override
    public Role save(Role role) {
        String roleName = role.getName();
        if(roleRpository.existsByName(roleName))
            throw new RuntimeException("Role with name "+ roleName +" already exists");
        return roleRpository.save(role);
    }
}
