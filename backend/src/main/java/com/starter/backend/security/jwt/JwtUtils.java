package com.starter.backend.security.jwt;

import java.security.Key;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

import com.starter.backend.model.User;
import com.starter.backend.security.UserPrincipal;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

@Component
public class JwtUtils {
  private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

  @Value("${app.auth.tokenSecret}")
  private String tokenSecret;

  @Value("${app.auth.tokenExpirationMsec}")
  private int tokenExpirationMsec;

  @Value("${app.auth.tokenRefreshExpirationMsec}")
  private int tokenRefreshExpirationMsec;

  @Value("${app.auth.jwtCookieName}")
  private String jwtCookieName;

  @Value("${app.auth.jwtRefreshCookieName}")
  private String jwtRefreshCookieName;

  public ResponseCookie generateJwtCookie(UserPrincipal userPrincipal) {
    String jwt = generateTokenFromEmail(userPrincipal.getEmail());
    return generateCookie(jwtCookieName, jwt, "/");
  }

  public ResponseCookie generateJwtCookie(User user) {
    String jwt = generateTokenFromEmail(user.getEmail());
    return generateCookie(jwtCookieName, jwt, "/");
  }

  public ResponseCookie generateRefreshJwtCookie(String refreshToken) {
    return generateCookie(jwtRefreshCookieName, refreshToken, "/auth/refreshtoken");
  }

  public String getJwtFromCookies(HttpServletRequest request) {
    return getCookieValueByName(request, jwtCookieName);
  }

  public String getJwtRefreshFromCookies(HttpServletRequest request) {
    return getCookieValueByName(request, jwtRefreshCookieName);
  }

  public ResponseCookie getCleanJwtCookie() {
    ResponseCookie cookie = ResponseCookie.from(jwtCookieName, null).path("/").build();
    return cookie;
  }

  public ResponseCookie getCleanJwtRefreshCookie() {
    ResponseCookie cookie = ResponseCookie.from(jwtRefreshCookieName, null).path("/auth/refreshtoken").build();
    return cookie;
  }

  public String getEmailFromJwtToken(String token) {
    return Jwts.parserBuilder().setSigningKey(key()).build()
        .parseClaimsJws(token).getBody().getSubject();
  }

  private Key key() {
    return Keys.hmacShaKeyFor(Decoders.BASE64.decode(tokenSecret));
  }

  public boolean validateJwtToken(String authToken) {
    try {
      Jwts.parserBuilder().setSigningKey(key()).build().parse(authToken);
      return true;
    } catch (MalformedJwtException e) {
      logger.error("Invalid JWT token: {}", e.getMessage());
    } catch (ExpiredJwtException e) {
      logger.error("JWT token is expired: {}", e.getMessage());
    } catch (UnsupportedJwtException e) {
      logger.error("JWT token is unsupported: {}", e.getMessage());
    } catch (IllegalArgumentException e) {
      logger.error("JWT claims string is empty: {}", e.getMessage());
    }

    return false;
  }

  public String generateTokenFromEmail(String email) {
    return Jwts.builder()
        .setSubject(email)
        .setIssuedAt(new Date())
        .setExpiration(new Date((new Date()).getTime() + tokenExpirationMsec))
        .signWith(key(), SignatureAlgorithm.HS256)
        .compact();
  }

  private ResponseCookie generateCookie(String name, String value, String path) {
    ResponseCookie cookie;
    if (name.compareTo(jwtRefreshCookieName) == 0) {
      cookie = ResponseCookie.from(name, value).path(path).maxAge(tokenRefreshExpirationMsec / 1000).httpOnly(true).build();
    } else if (name == jwtCookieName) {
      cookie = ResponseCookie.from(name, value).path(path).maxAge(tokenExpirationMsec / 1000).httpOnly(true)
          .build();
    } else {
      cookie = ResponseCookie.from(name, value).path(path).maxAge(24 * 60 * 60).httpOnly(true).build();
    }
    return cookie;
  }

  private String getCookieValueByName(HttpServletRequest request, String name) {
    Cookie cookie = WebUtils.getCookie(request, name);
    if (cookie != null) {
      return cookie.getValue();
    } else {
      return null;
    }
  }
}
