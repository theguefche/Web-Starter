package com.starter.backend.security;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.starter.backend.exception.TokenRefreshException;
import com.starter.backend.model.RefreshToken;
import com.starter.backend.model.User;
import com.starter.backend.repository.RefreshTokenRepository;
import com.starter.backend.repository.UserRepository;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

@Service
public class RefreshTokenService {
  @Value("${app.auth.tokenRefreshExpirationMsec}")
  private Long tokenRefreshExpirationMsec;

  @Autowired
  private RefreshTokenRepository refreshTokenRepository;

  @Autowired
  private UserRepository userRepository;

  public Optional<RefreshToken> findByToken(String token) {
    return refreshTokenRepository.findByToken(token);
  }

    public Optional<RefreshToken> findByUser(User user) {
    return refreshTokenRepository.findByUser(user);
  }

  public RefreshToken createRefreshToken(Long userId) {
    User user = userRepository.findById(userId).get();
    RefreshToken refreshToken = refreshTokenRepository.findByUser(user).orElse(new RefreshToken(user));
    refreshToken.setExpiryDate(Instant.now().plusMillis(tokenRefreshExpirationMsec));
    refreshToken.setToken(UUID.randomUUID().toString());
    refreshToken = refreshTokenRepository.save(refreshToken);

    return refreshToken;
  }

  public boolean isRefreshTokenExpired(RefreshToken token) {
    if (token.getExpiryDate().compareTo(Instant.now()) < 0)
      return true;
    else
      return false;

  }

  public RefreshToken verifyExpiration(RefreshToken token) {
    if (isRefreshTokenExpired(token)) {
      refreshTokenRepository.delete(token);
      throw new TokenRefreshException(token.getToken(), "Refresh token was expired. Please make a new signin request");
    }

    return token;
  }

  @Transactional
  public int deleteByUserId(Long userId) {
    return refreshTokenRepository.deleteByUser(userRepository.findById(userId).get());
  }

}
