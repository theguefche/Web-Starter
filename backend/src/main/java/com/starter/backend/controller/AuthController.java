package com.starter.backend.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import com.starter.backend.annotation.CurrentUser;
import com.starter.backend.annotation.controllers.RestApiController;
import com.starter.backend.enums.Provider;
import com.starter.backend.exception.BadRequestException;
import com.starter.backend.exception.TokenRefreshException;
import com.starter.backend.model.RefreshToken;
import com.starter.backend.model.User;
import com.starter.backend.payload.request.LoginRequest;
import com.starter.backend.payload.request.SignUpRequest;
import com.starter.backend.payload.response.ApiResponse;
import com.starter.backend.repository.UserRepository;
import com.starter.backend.security.RefreshTokenService;
import com.starter.backend.security.TokenProvider;
import com.starter.backend.security.UserPrincipal;
import com.starter.backend.security.jwt.JwtUtils;
import com.starter.backend.util.CookieUtils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

@RestApiController
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private TokenProvider tokenProvider;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private RefreshTokenService refreshTokenService;

    @Value("${app.auth.userIdentifier}")
    private String userIdentifier;

    @PostMapping("/auth/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getEmail(),
                        loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserPrincipal userDetails = (UserPrincipal) authentication.getPrincipal();

        ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails);

        // List<String> roles = userDetails.getAuthorities().stream()
        // .map(item -> item.getAuthority())
        // .collect(Collectors.toList());

        RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());
        ResponseCookie jwtRefreshCookie = jwtUtils.generateRefreshJwtCookie(refreshToken.getToken());
        ResponseCookie emailCookie = ResponseCookie.from(userIdentifier, userDetails.getEmail()).path("/").maxAge(-1)
                .build();

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
                .header(HttpHeaders.SET_COOKIE, jwtRefreshCookie.toString())
                .header(HttpHeaders.SET_COOKIE, emailCookie.toString())
                .body(new ApiResponse("Sign In Success !"));
    }

    @PostMapping("/auth/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequest signUpRequest) {

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            throw new BadRequestException("Email address already in use.");
        }

        // Create new user's account
        User user = User.builder()
                .fullName(signUpRequest.getFullName())
                .email(signUpRequest.getEmail())
                .password(passwordEncoder.encode(signUpRequest.getPassword()))
                .provider(Provider.LOCAL)
                .emailVerified(false)
                .build();

        userRepository.save(user);

        return ResponseEntity.ok(new ApiResponse("User registered successfully!"));
    }

    @PostMapping("/auth/signout")
    public ResponseEntity<?> logoutUser() {
        Object principle = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principle.toString() != "anonymousUser") {
            Long userId = ((UserPrincipal) principle).getId();
            refreshTokenService.deleteByUserId(userId);
        }

        ResponseCookie jwtCookie = jwtUtils.getCleanJwtCookie();
        ResponseCookie jwtRefreshCookie = jwtUtils.getCleanJwtRefreshCookie();

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
                .header(HttpHeaders.SET_COOKIE, jwtRefreshCookie.toString())
                .body(new ApiResponse("You've been signed out!"));
    }

    @PostMapping("/auth/refreshtoken")
    public ResponseEntity<?> refreshtoken(HttpServletRequest request) {
        String refreshToken = jwtUtils.getJwtRefreshFromCookies(request);
        if ((refreshToken != null) && (refreshToken.length() > 0)) {
            return refreshTokenService.findByToken(refreshToken)
                    .map(refreshTokenService::verifyExpiration)
                    .map(RefreshToken::getUser)
                    .map(user -> {
                        ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(user);

                        return ResponseEntity.ok()
                                .header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
                                .body(new ApiResponse("Token is refreshed successfully!"));
                    })
                    .orElseThrow(() -> new TokenRefreshException(refreshToken,
                            "Refresh token is not in database!"));
        }

        return ResponseEntity.badRequest().body(new ApiResponse("No Refresh Token Found!"));
    }

    @GetMapping("/auth/check")
    public ResponseEntity<?> check(@CurrentUser HttpServletRequest request) {
        User u = userRepository.findByEmail(CookieUtils.getCookie(request, userIdentifier).get().getValue())
                .orElse(null);
        RefreshToken token = refreshTokenService.findByUser(u).orElse(null);
        if (token != null) {
            if (refreshTokenService.isRefreshTokenExpired(token) == false) {
                return ResponseEntity.ok().body(new ApiResponse("Valid !"));
            } else {
                return ResponseEntity.status(HttpStatusCode.valueOf(400)).body(new ApiResponse("Invalid !"));
            }
        } else
            return ResponseEntity.status(HttpStatusCode.valueOf(400)).body(new ApiResponse("No Authentication !"));

    }

}
