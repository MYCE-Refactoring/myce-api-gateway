package com.myce.apigateway.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Slf4j
@Component
public class JwtUtil {

    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String REFRESH_TOKEN = "refresh_token";
    public static final String BEARER_PREFIX = "Bearer ";

    private static final String ROLE_CLAIM_KEY = "role";
    private static final String MEMBER_ID_CLAIM_KEY = "memberId";
    private static final String LOGIN_TYPE_CLAIM_KEY = "loginType";
    private static final String CATEGORY_CLAIM_KEY = "category";

    private final SecretKey secretKey;
    private final JwtParser jwtParser;

    public JwtUtil(@Value("${jwt.secret}") String secret) {
        this.secretKey = new SecretKeySpec(
                secret.getBytes(StandardCharsets.UTF_8),
                Jwts.SIG.HS256.key().build().getAlgorithm()
        );

        this.jwtParser = Jwts.parser().verifyWith(secretKey).build();
    }

    public String substringToken(String tokenValue) {
        if (StringUtils.hasText(tokenValue) && tokenValue.startsWith(BEARER_PREFIX)) {
            return tokenValue.substring(BEARER_PREFIX.length());
        }

        log.error("Not Found Token");
        throw new IllegalArgumentException("Not Found Token");
    }

    public Jws<Claims> getClaims(String token) {
        try {
            return jwtParser.parseSignedClaims(token);
        } catch (SecurityException | MalformedJwtException e) {
            log.error("Invalid JWT signature.", e);
            return null;
        } catch (UnsupportedJwtException e) {
            log.error("Unsupported JWT token.", e);
            return null;
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty.", e);
            return null;
        }
    }

    public boolean isExpired(Jws<Claims> claims) {
        return getExpirationTime(claims)
                .before(new Date());
    }

    private Date getExpirationTime(Jws<Claims> claims) {
        return claims
                .getPayload()
                .getExpiration();
    }

    public String getRoleFromToken(Jws<Claims> claims) {
        return claims
                .getPayload()
                .get(ROLE_CLAIM_KEY, String.class);
    }

    public Long getMemberIdFromToken(Jws<Claims> claims) {
        return claims
                .getPayload()
                .get(MEMBER_ID_CLAIM_KEY, Long.class);
    }

    public String getLoginTypeFromToken(Jws<Claims> claims) {
        return claims
                .getPayload()
                .get(LOGIN_TYPE_CLAIM_KEY, String.class);
    }

    public boolean isRefreshToken(Jws<Claims> claims) {
        return getCategoryFromToken(claims).equals(REFRESH_TOKEN);
    }

    private String getCategoryFromToken(Jws<Claims> claims) {
        return claims
                .getPayload()
                .get(CATEGORY_CLAIM_KEY, String.class);
    }
}
