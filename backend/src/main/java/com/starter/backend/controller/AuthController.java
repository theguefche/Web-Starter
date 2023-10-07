package com.starter.backend.controller;

import java.net.URI;
import java.time.LocalDateTime;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.starter.backend.enums.Provider;
import com.starter.backend.exception.BadRequestException;
import com.starter.backend.model.User;
import com.starter.backend.payload.ApiResponse;
import com.starter.backend.payload.ExceptionResponse;
import com.starter.backend.payload.LoginRequest;
import com.starter.backend.payload.SignUpRequest;
import com.starter.backend.repository.UserRepository;
import com.starter.backend.security.CurrentUser;
import com.starter.backend.security.TokenProvider;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;

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

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest,
            HttpServletResponse response) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getEmail(),
                        loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String token = tokenProvider.createToken(authentication);

        tokenProvider.setAuthCookies(response, token);

        return ResponseEntity.ok("Success !");
    }

    @GetMapping("/check")
    public ResponseEntity<?> check(@CurrentUser HttpServletRequest request) {
        if (tokenProvider.validateToken(tokenProvider.getTokenCookie(request).get().getValue())) {
            return ResponseEntity.ok().body("Valid !");

        } else {
            return ResponseEntity.status(HttpStatusCode.valueOf(400)).body("Invalid !");

        }
    }

    @GetMapping("/a")
    public String heString() throws IllegalAccessException, MethodArgumentNotValidException {
        throw new MethodArgumentNotValidException(null, null);
    }

    @PostMapping("/b")
    public ResponseEntity<?> hadsaResponseEntity(@Valid @RequestBody LoginRequest jsoString)
            throws JsonMappingException, JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        // objectMapper.readTree(jsoString);

        return ResponseEntity.ok(jsoString);
    }

    @GetMapping("/c")
    public ResponseEntity<?> tResponseEntity() {
        ExceptionResponse x = ExceptionResponse.builder().cause("null").message("asd").trace("expired").build();

        return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(x);
    }

    @GetMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        String token = tokenProvider.getTokenCookie(request).get().getValue();
        ;
        if (token != null) {
            tokenProvider.invalidateToken(token);
            return ResponseEntity.ok().body("Logout Success !");
        } else {
            return ResponseEntity.badRequest().body("Logout Failed ! Token Unavailable");
        }
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequest signUpRequest) {
        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            // return ResponseEntity.badRequest().body("Email Already In Use !");
            throw new BadRequestException("Email address already in use.");
        }

        // Creating user's account
        User user = User.builder()
                .name(signUpRequest.getName())
                .email(signUpRequest.getEmail())
                .password(signUpRequest.getPassword())
                .provider(Provider.LOCAL)
                .emailVerified(false)
                .build();

        user.setPassword(passwordEncoder.encode(user.getPassword()));

        User result = userRepository.save(user);

        URI location = ServletUriComponentsBuilder
                .fromCurrentContextPath().path("/user/me")
                .buildAndExpand(result.getId()).toUri();

        return ResponseEntity.created(location)
                .body(new ApiResponse(true, "User registered successfully@"));
    }

}



