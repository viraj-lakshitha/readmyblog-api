package io.readmyblog.readmyblogapi.auth;

import io.readmyblog.readmyblogapi.configuration.AppProperties;
import io.readmyblog.readmyblogapi.core.TokenType;
import io.readmyblog.readmyblogapi.exception.BadRequestException;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class TokenProvider {

    private static final Logger logger = LoggerFactory.getLogger(TokenProvider.class);

    private AppProperties appProperties;

    public TokenProvider(AppProperties appProperties) {
        this.appProperties = appProperties;
    }

    public AuthTokens createToken(Authentication authentication) {
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

        Date now = new Date();
        Date accessTokenExpiryDate = new Date(now.getTime() + getTokenExpirationByType(TokenType.ACCESS));
        Date refreshTokenExpiryDate = new Date(now.getTime() + getTokenExpirationByType(TokenType.REFRESH));

        String accessToken = Jwts.builder()
                .setSubject(userPrincipal.getId())
                .setIssuedAt(new Date())
                .setExpiration(accessTokenExpiryDate)
                .signWith(SignatureAlgorithm.HS512, getAuthTokenSecretByType(TokenType.ACCESS))
                .compact();

        String refreshToken = Jwts.builder()
                .setSubject(userPrincipal.getId())
                .setIssuedAt(new Date())
                .setExpiration(refreshTokenExpiryDate)
                .signWith(SignatureAlgorithm.HS512, getAuthTokenSecretByType(TokenType.REFRESH))
                .compact();

        return new AuthTokens(accessToken, refreshToken);
    }

    public String createTokenFromRefreshToken(Authentication authentication, String refreshToken) {
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

        // Check if the user ID matches with the currently authenticated principal
        if (!getUserIdFromToken(refreshToken, TokenType.REFRESH).equals(userPrincipal.getId())) {
            throw new BadRequestException("invalid.token.exchange");
        }
        // Validate refresh token
        if (!isValidToken(refreshToken, TokenType.REFRESH)) {
            throw new BadRequestException("jwt.parser.error");
        }

        Date now = new Date();
        Date accessTokenExpiryDate = new Date(now.getTime() + getTokenExpirationByType(TokenType.ACCESS));

        return Jwts.builder()
                .setSubject(userPrincipal.getId())
                .setIssuedAt(new Date())
                .setExpiration(accessTokenExpiryDate)
                .signWith(SignatureAlgorithm.HS512, appProperties.getAuth().getAccessTokenSecret())
                .compact();
    }

    public String getUserIdFromToken(String token, TokenType tokenType) {
        String tokenSecret = getAuthTokenSecretByType(tokenType);
        Claims claims = Jwts.parser()
                .setSigningKey(tokenSecret)
                .parseClaimsJws(token)
                .getBody();

        return claims.getSubject();
    }

    public boolean isValidToken(String authToken, TokenType tokenType) {
        String tokenSecret = getAuthTokenSecretByType(tokenType);
        try {
            Jwts.parser().setSigningKey(tokenSecret).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException ex) {
            logger.error("Invalid JWT signature");
        } catch (MalformedJwtException ex) {
            logger.error("Invalid JWT token");
        } catch (ExpiredJwtException ex) {
            logger.error("Expired JWT token");
        } catch (UnsupportedJwtException ex) {
            logger.error("Unsupported JWT token");
        } catch (IllegalArgumentException ex) {
            logger.error("JWT claims string is empty.");
        }
        return false;
    }

    private String getAuthTokenSecretByType(TokenType tokenType) {
        switch (tokenType) {
            case ACCESS:
                return appProperties.getAuth().getAccessTokenSecret();
            case REFRESH:
                return appProperties.getAuth().getRefreshTokenSecret();
            default:
                logger.error("Unknown token type {}", tokenType);
                return null;
        }
    }

    private long getTokenExpirationByType(TokenType tokenType) {
        switch (tokenType) {
            case ACCESS:
                return appProperties.getAuth().getAccessTokenExpiration();
            case REFRESH:
                return appProperties.getAuth().getRefreshTokenExpiration();
            default:
                logger.error("Unknown token type {}", tokenType);
                return 0L;
        }
    }

}
