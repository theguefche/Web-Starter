package com.starter.backend.security.oauth2;

import static com.starter.backend.security.oauth2.HttpCookieOAuth2AuthorizationRequestRepository.REDIRECT_URI_PARAM_COOKIE_NAME;

import java.io.IOException;
import java.net.URI;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import com.starter.backend.config.AppProperties;
import com.starter.backend.exception.BadRequestException;
import com.starter.backend.model.RefreshToken;
import com.starter.backend.security.RefreshTokenService;
import com.starter.backend.security.TokenProvider;
import com.starter.backend.security.UserPrincipal;
import com.starter.backend.security.jwt.JwtUtils;
import com.starter.backend.util.CookieUtils;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Value;

@Component
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private TokenProvider tokenProvider;

    private AppProperties appProperties;

    private HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private RefreshTokenService refreshTokenService;

    @Autowired
    OAuth2AuthenticationSuccessHandler(TokenProvider tokenProvider, AppProperties appProperties,
            HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository) {
        this.tokenProvider = tokenProvider;
        this.appProperties = appProperties;
        this.httpCookieOAuth2AuthorizationRequestRepository = httpCookieOAuth2AuthorizationRequestRepository;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {

        String targetUrl = determineTargetUrl(request, response, authentication);

        if (response.isCommitted()) {
            logger.debug("Response has already been committed. Unable to redirect to " + targetUrl);
            return;
        }
        clearAuthenticationAttributes(request, response);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) {
        Optional<String> redirectUri = CookieUtils.getCookie(request, REDIRECT_URI_PARAM_COOKIE_NAME)
                .map(Cookie::getValue);

        if (redirectUri.isPresent() && !isAuthorizedRedirectUri(redirectUri.get())) {
            throw new BadRequestException(
                    "Sorry! We've got an Unauthorized Redirect URI and can't proceed with the authentication");
        }

        String targetUrl = redirectUri.orElse(getDefaultTargetUrl());

        // String token = tokenProvider.createToken(authentication);
        // tokenProvider.setAuthCookies(response, token);

        UserPrincipal userDetails = (UserPrincipal) authentication.getPrincipal();

        ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());
        ResponseCookie jwtRefreshCookie = jwtUtils.generateRefreshJwtCookie(refreshToken.getToken());
        ResponseCookie emailCookie = ResponseCookie
                .from(appProperties.getAuth().getUserIdentifier(), userDetails.getEmail()).path("/").secure(appProperties.getAuth().isSecured_deploy()).maxAge(-1).build();

        response.addHeader(HttpHeaders.SET_COOKIE, jwtCookie.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, jwtRefreshCookie.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, emailCookie.toString());

        // add parameter to determine of ot's mobile to send string instead of cookies

        logger.info(targetUrl);
        return UriComponentsBuilder.fromUriString(targetUrl)
                .build().toUriString();
    }

    protected void clearAuthenticationAttributes(HttpServletRequest request, HttpServletResponse response) {
        super.clearAuthenticationAttributes(request);
        // httpCookieOAuth2AuthorizationRequestRepository.removeAuthorizationRequestCookies(request,
        // response);
    }

    private boolean isAuthorizedRedirectUri(String uri) {
        URI clientRedirectUri = URI.create(uri);

        return appProperties.getOauth2().getAuthorizedRedirectUris()
                .stream()
                .anyMatch(authorizedRedirectUri -> {
                    // Only validate host and port. Let the clients use different paths if they want
                    // to
                    URI authorizedURI = URI.create(authorizedRedirectUri);
                    if (authorizedURI.getHost().equalsIgnoreCase(clientRedirectUri.getHost())
                            && authorizedURI.getPort() == clientRedirectUri.getPort()) {
                        return true;
                    }
                    return false;
                });
    }
}
