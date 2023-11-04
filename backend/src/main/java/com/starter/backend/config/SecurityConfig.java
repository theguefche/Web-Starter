package com.starter.backend.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
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
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;

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
@EnableWebSecurity(debug = true) // debug mode
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

        // @Autowired
        // private HttpCookieOAuth2AuthorizationRequestRepository
        // httpCookieOAuth2AuthorizationRequestRepository;

        @Bean
        public TokenAuthenticationFilter tokenAuthenticationFilter() {
                return new TokenAuthenticationFilter();
        }

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
        @Order(1)
        public SecurityFilterChain restSecurityFilterChain(HttpSecurity http)
                        throws Exception {
                String API_PATH = "/api";

                http
                                .securityMatcher(API_PATH + "/**")
                                .authorizeHttpRequests((authz) -> authz
                                                .requestMatchers(API_PATH + "/auth/**", API_PATH + "/oauth2/**")
                                                .permitAll()
                                                .requestMatchers(HttpMethod.POST, API_PATH + "/user").permitAll()
                                                .requestMatchers(HttpMethod.GET, API_PATH + "/csrf/**").permitAll()
                                                .anyRequest()
                                                .authenticated())
                                .httpBasic(Customizer.withDefaults());

                http.headers(headers -> headers.xssProtection(
                                xss -> xss.headerValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK))
                                .contentSecurityPolicy(
                                                cps -> cps.policyDirectives("script-src 'self'")))
                                .cors(Customizer.withDefaults())
                                .csrf((csrf) -> csrf
                                                .csrfTokenRepository(new CookieCsrfTokenRepository()))
                                .sessionManagement(management -> management
                                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

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
                                                .accessDeniedHandler(new RestAuthenticationEntryPoint())
                                                .authenticationEntryPoint(new RestAuthenticationEntryPoint()))

                                .addFilterBefore(tokenAuthenticationFilter(),
                                                UsernamePasswordAuthenticationFilter.class);

                return http.build();
        }

        @Bean
        @Order(2)
        public SecurityFilterChain webSecurityFilterChain(HttpSecurity http) throws Exception {
                String API_PATH = "/doc";
                http
                                .cors((cors) -> cors.disable())
                                .csrf((csrf) -> csrf.disable())
                                .securityMatcher(API_PATH + "/**")
                                .authorizeHttpRequests((authz) -> authz
                                                .requestMatchers(API_PATH + "/**").authenticated()
                                                .requestMatchers("/resources/**").permitAll()
                                                .anyRequest().authenticated())
                                .formLogin(form -> form
                                                .loginPage(API_PATH + "/login")
                                                .permitAll().defaultSuccessUrl(API_PATH + "/api-docs-ui"));

                return http.build();
        }

}
