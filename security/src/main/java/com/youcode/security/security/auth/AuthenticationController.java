package com.youcode.security.security.auth;

import com.youcode.security.entities.AppUser;
import com.youcode.security.security.AuthenticationService;
import com.youcode.security.web.dto.SignInRequest;
import com.youcode.security.web.dto.SignUpRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import javax.validation.ValidationException;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @PostMapping("/login")
    public ResponseEntity<JwtAuthenticationResponse> login(@RequestBody @Valid SignInRequest credential) {
        JwtAuthenticationResponse result = authenticationService.signin(credential);

        return ResponseEntity.ok(result);
    }

    @PostMapping("/register")
    public ResponseEntity<JwtAuthenticationResponse> signup(@RequestBody @Valid SignUpRequest register) throws ValidationException {
        JwtAuthenticationResponse result = authenticationService.signup(register);

        return ResponseEntity.ok(result);
    }

    @GetMapping("/me")
    public ResponseEntity<AppUser> me() {
        AppUser result = authenticationService.me();
        return ResponseEntity.ok(result);
    }

    @PostMapping("/token/refresh")
    public ResponseEntity<JwtAuthenticationResponse> refreshToken(HttpServletRequest request) throws ValidationException {
        String authorization = request.getHeader("Authorization");
        if(authorization == null || !authorization.startsWith("Bearer ")) {
            throw new RuntimeException("Refresh token is missing"); // TODO add new exception of unauthorized
        }
        String token = authorization.substring(7);
        JwtAuthenticationResponse result = authenticationService.refreshToken(token);
        return ResponseEntity.ok(result);
    }
}