package io.readmyblog.readmyblogapi.controller;

import io.readmyblog.readmyblogapi.auth.AuthTokens;
import io.readmyblog.readmyblogapi.auth.TokenProvider;
import io.readmyblog.readmyblogapi.core.AuthProvider;
import io.readmyblog.readmyblogapi.core.Role;
import io.readmyblog.readmyblogapi.core.model.User;
import io.readmyblog.readmyblogapi.core.vo.AuthResponse;
import io.readmyblog.readmyblogapi.core.vo.LoginRequest;
import io.readmyblog.readmyblogapi.core.vo.SignUpRequest;
import io.readmyblog.readmyblogapi.core.vo.TokenRefreshRequest;
import io.readmyblog.readmyblogapi.exception.BadRequestException;
import io.readmyblog.readmyblogapi.exception.ResourceNotFoundException;
import io.readmyblog.readmyblogapi.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.validation.Valid;
import java.net.URI;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private TokenProvider tokenProvider;


    @PostMapping("/refresh")
    public ResponseEntity<?> refreshAccessToken(@Valid @RequestBody TokenRefreshRequest tokenRefreshRequest) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String accessToken = tokenProvider.createTokenFromRefreshToken(authentication, tokenRefreshRequest.getRefreshToken());

        return ResponseEntity.ok(new AuthResponse(accessToken));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        User user = userRepository.findByEmail(loginRequest.getEmail())
                .orElseThrow(() -> new ResourceNotFoundException("User not found for the email "+loginRequest.getEmail()));

        if (!user.getIsActive()) {
            throw new BadRequestException("Account Not Activated");
        }

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getEmail(),
                        loginRequest.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        AuthTokens authTokens = tokenProvider.createToken(authentication);

        userRepository.save(user);
        return ResponseEntity.ok(new AuthResponse(authTokens));
    }

    @PostMapping("/signup")
    public ResponseEntity<User> registerUser(@Valid @RequestBody SignUpRequest signUpRequest) {
        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            throw new BadRequestException("Email address already in use.");
        }

        User user = new User();
        user.setName(signUpRequest.getName());
        user.setEmail(signUpRequest.getEmail());
        user.setPassword(signUpRequest.getPassword());
        user.setProvider(AuthProvider.local);
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRole(Role.ROLE_USER);
        user.setIsActive(true);
        User result = userRepository.save(user);

        URI location = ServletUriComponentsBuilder
                .fromCurrentContextPath().path("/v1/users/me")
                .buildAndExpand(result.getId()).toUri();

        ResponseEntity.created(location).build();
        return ResponseEntity.ok(user);
    }
}
