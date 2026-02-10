package com.myce.apigateway.filter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.myce.apigateway.config.SecurityEndpoints;
import com.myce.apigateway.filter.dto.InternalHeaderKey;
import com.myce.apigateway.filter.dto.InternalUser;
import com.myce.apigateway.repository.TokenBlackListRepository;
import com.myce.apigateway.util.JsonUtil;
import com.myce.apigateway.util.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import java.util.Arrays;
import java.util.Map;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {

    private static final String INVALID_TOKEN_CODE = "INVALID_TOKEN";
    private static final String EXPIRED_TOKEN_CODE = "EXPIRED_TOKEN";

    private static final String LOGOUT_URI = "/api/auth/logout";

    private final JwtUtil jwtUtil;
    private final TokenBlackListRepository tokenBlackListRepository;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    public JwtAuthenticationFilter(JwtUtil jwtUtil, TokenBlackListRepository tokenBlackListRepository) {
        super(Config.class);
        this.jwtUtil = jwtUtil;
        this.tokenBlackListRepository = tokenBlackListRepository;
    }

    @Getter
    @Setter
    public static class Config {
        private String internalAuthValue;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (ServerWebExchange exchange, GatewayFilterChain chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            ServerHttpResponse response = exchange.getResponse();

            String uri = request.getURI().getPath();
            String method = request.getMethod().name();

            HttpHeaders headers = request.getHeaders();
            String token = headers.getFirst(JwtUtil.AUTHORIZATION_HEADER);
            log.debug("[JwtAuthenticationFilter] Input uri={}, method={}", uri, method);
            log.info("uri={}, Authorization={}", uri, token);


            // jwt 존재 여부 및 유효성 검사
            if (isPermitAll(method, uri) && (token == null || token.isEmpty())) {
                ServerHttpRequest mutatedRequest = buildSecuredRequest(request, config.internalAuthValue);
                ServerWebExchange mutatedExchange = exchange.mutate().request(mutatedRequest).build();

                log.debug("[JwtAuthenticationFilter] Permit all uri. uri={}, method={}", uri, method);
                return chain.filter(mutatedExchange);
            }

            if (token == null || token.isEmpty()) {
                log.debug("[JwtAuthenticationFilter] Not exist token. uri={}, method={}", uri, method);
                return getInvalidTokenCodeError(response);
            }

            // 토큰만 추출
            String accessToken = jwtUtil.substringToken(token);

            // 토큰 검증
            Jws<Claims> claims;
            try {
                claims = jwtUtil.getClaims(accessToken);
                if (claims == null) return getInvalidTokenCodeError(response);
                if (jwtUtil.isExpired(claims)) return getExpiredTokenError(response);
            } catch (ExpiredJwtException e) {
                log.info("Expire Token. uri={}, method={}", uri, method);
                return getExpiredTokenError(response);
            }

            return tokenBlackListRepository.containsByAccessToken(accessToken)
                    .flatMap(exists -> {
                        if (exists) return getInvalidTokenCodeError(response);

                        String role = jwtUtil.getRoleFromToken(claims);
                        String loginType = jwtUtil.getLoginTypeFromToken(claims);
                        Long memberId = jwtUtil.getMemberIdFromToken(claims);

                        if (role == null || loginType == null || memberId == null) {
                            log.info("Not exist user info. role={}, loginType={}, memberId={}", role, loginType, memberId);
                            return getInvalidTokenCodeError(response);
                        }

                        InternalUser internalUser = new InternalUser(role, loginType, memberId);
                        ServerHttpRequest mutatedRequest = buildSecuredRequest
                                (request, internalUser, config.internalAuthValue, accessToken);
                        ServerWebExchange mutatedExchange =
                                exchange.mutate().request(mutatedRequest).build();

                        return chain.filter(mutatedExchange);
                    });
        };
    }

    private ServerHttpRequest buildSecuredRequest(
            ServerHttpRequest request,
            InternalUser internalUser,
            String internalAuthValue,
            String token
    ) {
        return request.mutate()
                .headers(headers -> {
                    headers.entrySet().removeIf(
                            h -> h.getKey().startsWith(InternalHeaderKey.INTERNAL_HEADER_PREFIX)
                                    || h.getKey().equalsIgnoreCase(HttpHeaders.AUTHORIZATION)
                    );

                    headers.add(InternalHeaderKey.INTERNAL_AUTH, internalAuthValue);
                    headers.add(InternalHeaderKey.INTERNAL_ROLE, internalUser.role());
                    headers.add(InternalHeaderKey.INTERNAL_LOGIN_TYPE, internalUser.loginType());
                    headers.add(InternalHeaderKey.INTERNAL_MEMBER_ID, String.valueOf(internalUser.memberId()));

                    if (request.getURI().getPath().equals(LOGOUT_URI)) {
                        headers.add(InternalHeaderKey.INTERNAL_ACCESS_TOKEN, token);
                    }
                })
                .build();
    }

    private ServerHttpRequest buildSecuredRequest(ServerHttpRequest request, String internalAuthValue) {
        return request.mutate()
                .headers(headers -> {
                    headers.entrySet().removeIf(
                            h -> h.getKey().startsWith(InternalHeaderKey.INTERNAL_HEADER_PREFIX)
                                    || h.getKey().equalsIgnoreCase(HttpHeaders.AUTHORIZATION)
                    );

                    headers.add(InternalHeaderKey.INTERNAL_AUTH, internalAuthValue);
                })
                .build();
    }

    private Mono<Void> getInvalidTokenCodeError(ServerHttpResponse response) {
        return setErrorResponse(response, INVALID_TOKEN_CODE);
    }

    private Mono<Void> getExpiredTokenError(ServerHttpResponse response) {
        return setErrorResponse(response, EXPIRED_TOKEN_CODE);
    }

    private Mono<Void> setErrorResponse(ServerHttpResponse response, String code) {
        if (response.isCommitted()) {
            return Mono.empty();
        }

        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().set(HttpHeaders.CONTENT_TYPE, "application/json;charset=UTF-8");

        Map<String, String> body = Map.of("code", code);
        byte[] bytes = null;
        try {
            bytes = JsonUtil.convertToBytes(body);
        } catch (JsonProcessingException e) {
            log.error("Fail to convert to byte. body={}", body, e);
        }
        DataBuffer buffer = response.bufferFactory().wrap(bytes);
        return response.writeWith(Mono.just(buffer));
    }

    private boolean isPermitAll(String method, String path) {
        if(isExist(SecurityEndpoints.ETC_PERMIT_ALL, path)) return true;

        if(HttpMethod.GET.name().equals(method)) {
            return isExist(SecurityEndpoints.GET_PERMIT_ALL, path);
        }
        if(HttpMethod.POST.name().equals(method)) {
            return isExist(SecurityEndpoints.POST_PERMIT_ALL, path);
        }
        if(HttpMethod.PATCH.name().equals(method)) {
            return isExist(SecurityEndpoints.PATCH_PERMIT_ALL, path);
        }
        if(HttpMethod.DELETE.name().equals(method)) {
            return isExist(SecurityEndpoints.DELETE_PERMIT_ALL, path);
        }

        return false;
    }

    private boolean isExist(String[] patterns, String path) {
        return Arrays.stream(patterns).anyMatch(p -> pathMatcher.match(p, path));
    }
}
