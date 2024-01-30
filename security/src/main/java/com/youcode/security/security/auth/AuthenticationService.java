package com.youcode.security.security.auth;

import com.youcode.security.entities.AppUser;
import com.youcode.security.security.auth.JwtAuthenticationResponse;
import com.youcode.security.web.dto.SignInRequest;
import com.youcode.security.web.dto.SignUpRequest;

public interface AuthenticationService {

    JwtAuthenticationResponse signup(SignUpRequest request);

    JwtAuthenticationResponse signin(SignInRequest request);

    JwtAuthenticationResponse refreshToken(String refreshToken);

    AppUser me();
}