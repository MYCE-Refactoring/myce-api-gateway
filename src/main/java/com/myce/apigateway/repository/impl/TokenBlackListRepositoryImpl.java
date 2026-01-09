package com.myce.apigateway.repository.impl;

import com.myce.apigateway.repository.TokenBlackListRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class TokenBlackListRepositoryImpl implements TokenBlackListRepository {

    private static final String KEY_FORMAT = "token:blacklist:%s";

    private final ReactiveRedisTemplate<String, String> redisTemplate;

    @Override
    public Mono<Boolean> containsByAccessToken(String accessToken) {
        String key = String.format(KEY_FORMAT, accessToken);
        return redisTemplate.hasKey(key);
    }
}

