package com.starter.backend.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;

import com.starter.backend.security.CustomUserDetailsService;
import com.starter.backend.security.RestAuthenticationEntryPoint;
import com.starter.backend.security.TokenAuthenticationFilter;
import com.starter.backend.security.doc.DocFilter;
import com.starter.backend.security.doc.DocSuccessHandler;
import com.starter.backend.security.oauth2.CustomOAuth2UserService;
import com.starter.backend.security.oauth2.HttpCookieOAuth2AuthorizationRequestRepository;
import com.starter.backend.security.oauth2.OAuth2AuthenticationFailureHandler;
import com.starter.backend.security.oauth2.OAuth2AuthenticationSuccessHandler;

import jakarta.annotation.Resource;
import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity(debug = true) // debug mode
@RequiredArgsConstructor
public class SecurityConfig {

        @Value("${app.docs.username}")
        private String docs_username;

        @Value("${app.docs.password}")
        private String docs_password;

        @Value("${app.docs.role}")
        private String docs_role;

   
        @Resource
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
        public DocFilter docFilter() {
                return new DocFilter();
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
                                // .authenticationProvider(inMemoryAuthenticationProviderFirst())
                                // .userDetailsService(customUserDetailsService)
                                .addFilterBefore(tokenAuthenticationFilter(),
                                                UsernamePasswordAuthenticationFilter.class)

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
                                // .csrf().disable()
                                .sessionManagement(management -> management
                                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

                http
                                .oauth2Login(oauth2Login -> oauth2Login
                                                .authorizationEndpoint(endpoint -> endpoint
                                                                .baseUri(API_PATH+"/oauth2/authorize")
                                                                .authorizationRequestRepository(
                                                                                cookieAuthorizationRequestRepository()))
                                                .redirectionEndpoint(endpoint -> endpoint
                                                                .baseUri(API_PATH+"/oauth2/callback/*"))
                                                .userInfoEndpoint(userInfo -> userInfo
                                                                .userService(customOAuth2UserService))
                                                .successHandler(oAuth2AuthenticationSuccessHandler)
                                                .failureHandler(oAuth2AuthenticationFailureHandler));
                http
                                .exceptionHandling(exceptionHandling -> exceptionHandling
                                                .accessDeniedHandler(new RestAuthenticationEntryPoint())
                                                .authenticationEntryPoint(new RestAuthenticationEntryPoint()));

                return http.build();
        }

        @Bean
        public AuthenticationProvider inMemoryAuthenticationProviderFirst() {
                DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
                authProvider.setUserDetailsService(customUserDetailsService);
                authProvider.setPasswordEncoder(passwordEncoder());
                return authProvider;
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
                                                .requestMatchers(API_PATH + "/**")
                                                .hasRole(docs_role)
                                                .requestMatchers("/resources/**").permitAll()
                                                .anyRequest().authenticated())
                                .authenticationProvider(inMemoryAuthenticationProvider())
                                .sessionManagement((session) -> session
                                                .sessionCreationPolicy(SessionCreationPolicy.ALWAYS))
                                // .userDetailsService(users())
                                .formLogin(form -> form
                                                .loginPage(API_PATH + "/login").successHandler(docSuccessHandler())
                                                .failureUrl(API_PATH + "/login?error").permitAll()

                                )
                // .logout((logout) -> logout.permitAll())
                ;

                return http.build();
        }

        @Bean
        public DocSuccessHandler docSuccessHandler() {
                return new DocSuccessHandler();
        }

        @Bean
        public AuthenticationProvider inMemoryAuthenticationProvider() {
                InMemoryUserDetailsManager userDetailsManager = new InMemoryUserDetailsManager();
                userDetailsManager.createUser(User.builder()
                                .username(docs_username)
                                .password(docs_password)
                                .roles(docs_role)
                                .build());

                DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
                authProvider.setUserDetailsService(userDetailsManager);
                return authProvider;
        }

}
