package com.starter.backend.security;

import java.security.Key;
import java.util.Date;
import java.util.Optional;
import java.util.function.Function;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.Cache.ValueWrapper;
import org.springframework.cache.CacheManager;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import com.starter.backend.config.AppProperties;
import com.starter.backend.repository.UserRepository;
import com.starter.backend.util.CookieUtils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Service
public class TokenProvider {

    private static final Logger logger = LoggerFactory.getLogger(TokenProvider.class);

    private AppProperties appProperties;

    @Autowired
    UserRepository userRepository;

    @Autowired
    private CacheManager cacheManager;

    public TokenProvider(AppProperties appProperties) {
        this.appProperties = appProperties;
    }

    public String createToken(Authentication authentication) {
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + appProperties.getAuth().getTokenExpirationMsec());

        return Jwts.builder()
                .setSubject(Long.toString(userPrincipal.getId()))
                .setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(appProperties.getAuth().getTokenSecret());
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public Long getUserIdFromToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(appProperties.getAuth().getTokenSecret())
                .build()
                .parseClaimsJws(token)
                .getBody();

        return Long.parseLong(claims.getSubject());
    }

    public String getUserEmailFromToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(appProperties.getAuth().getTokenSecret())
                .build()
                .parseClaimsJws(token)
                .getBody();

        return userRepository.findById(Long.parseLong(claims.getSubject())).get().getEmail();
    }

    public boolean isTokenBlacklisted(String token) {
        Cache invalidTokensCache = cacheManager.getCache("invalidTokens");
        ValueWrapper invalidTokenWrapper = invalidTokensCache.get(token);
        if (invalidTokenWrapper == null) {
            return false;
        }
        return true;
    }

    public boolean validateToken(String authToken) {
        try {

            if(isTokenBlacklisted(authToken)) {
                throw new ExpiredJwtException(null, null, "Blacklisted Token !", null);
            }

            Jwts.parserBuilder()
                    .setSigningKey(appProperties.getAuth().getTokenSecret())
                    .build()
                    .parseClaimsJws(authToken)
                    .getBody();
            return true;

        } catch (SecurityException | ExpiredJwtException | UnsupportedJwtException | MalformedJwtException
                | IllegalArgumentException ex) {
            logger.error("JWT token validation failed: " + ex.getMessage());
        }
        return false;
    }

    public void setAuthCookies(HttpServletResponse response, String value) {

        int exp = (int) appProperties.getAuth().getTokenExpirationMsec() / 1000;

        Cookie tCookie = new Cookie(appProperties.getAuth().getTokenName().toString(), value);
        tCookie.setPath("/");
        tCookie.setHttpOnly(true);
        tCookie.setSecure(false);
        tCookie.setMaxAge(exp);
        response.addCookie(tCookie);

        Cookie usCookie = new Cookie(appProperties.getAuth().getUserIdentifier().toString(),
                getUserEmailFromToken(value));
        usCookie.setPath("/");
        usCookie.setHttpOnly(false);
        usCookie.setSecure(false);
        usCookie.setMaxAge(exp);
        response.addCookie(usCookie);

    }

    public Optional<Cookie> getTokenCookie(HttpServletRequest request) {
        return CookieUtils.getCookie(request, appProperties.getAuth().getTokenName());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public void invalidateToken(String token) {
        Cache invalidTokensCache = cacheManager.getCache("invalidTokens");
        invalidTokensCache.put(token, true);
    }

    public boolean isTokenExpiredV2(String token) {
        try {
            extractExpiration(token).before(new Date());
            return false;
        } catch (Exception e) {
            return true;
        }

    }

}
