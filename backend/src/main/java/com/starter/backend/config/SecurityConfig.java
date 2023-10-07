package com.starter.backend.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.starter.backend.repository.UserRepository;
import com.starter.backend.security.CustomUserDetailsService;
import com.starter.backend.security.RestAuthenticationEntryPoint;
import com.starter.backend.security.TokenAuthenticationFilter;
import com.starter.backend.security.oauth2.CustomOAuth2UserService;
import com.starter.backend.security.oauth2.HttpCookieOAuth2AuthorizationRequestRepository;
import com.starter.backend.security.oauth2.OAuth2AuthenticationFailureHandler;
import com.starter.backend.security.oauth2.OAuth2AuthenticationSuccessHandler;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity(debug = true)
@RequiredArgsConstructor
public class SecurityConfig {

        @Autowired
        UserRepository repository;

        @Autowired
        private CustomUserDetailsService customUserDetailsService;

        @Autowired
        private CustomOAuth2UserService customOAuth2UserService;

        @Autowired
        private OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;

        @Autowired
        private OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;

        @Autowired
        private HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository;

        @Bean
        public TokenAuthenticationFilter tokenAuthenticationFilter() {
                return new TokenAuthenticationFilter();
        }

        /*
         * By default, Spring OAuth2 uses
         * HttpSessionOAuth2AuthorizationRequestRepository to save
         * the authorization request. But, since our service is stateless, we can't save
         * it in
         * the session. We'll save the request in a Base64 encoded cookie instead.
         */
        @Bean
        public HttpCookieOAuth2AuthorizationRequestRepository cookieAuthorizationRequestRepository() {
                return new HttpCookieOAuth2AuthorizationRequestRepository();
        }

        @Bean
        public PasswordEncoder passwordEncoder() {
                return new BCryptPasswordEncoder();
        }

        @Bean
        public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
                return config.getAuthenticationManager();
        }

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
                http
                                .cors(Customizer.withDefaults())
                                // .cors(cors -> cors.disable())
                                .csrf(csrf -> csrf.disable())
                                .sessionManagement(management -> management
                                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                                .authorizeHttpRequests((authz) -> authz
                                                .requestMatchers("/auth/**", "/oauth2/**")
                                                .permitAll()
                                                .anyRequest()
                                                .authenticated());
                http
                                .oauth2Login(oauth2Login -> oauth2Login
                                                .authorizationEndpoint(endpoint -> endpoint
                                                                .baseUri("/oauth2/authorize")
                                                                .authorizationRequestRepository(
                                                                                cookieAuthorizationRequestRepository()))
                                                .redirectionEndpoint(endpoint -> endpoint
                                                                .baseUri("/oauth2/callback/*"))
                                                .userInfoEndpoint(userInfo -> userInfo
                                                                .userService(customOAuth2UserService))
                                                .successHandler(oAuth2AuthenticationSuccessHandler)
                                                .failureHandler(oAuth2AuthenticationFailureHandler));
                http
                                .exceptionHandling(exceptionHandling -> exceptionHandling
                                                // .accessDeniedHandler(new RestAuthenticationEntryPoint())
                                                .authenticationEntryPoint(new RestAuthenticationEntryPoint()))

                                .addFilterBefore(tokenAuthenticationFilter(),
                                                UsernamePasswordAuthenticationFilter.class);
                http
                                .httpBasic(Customizer.withDefaults());

                return http.build();
        }
}
