package com.myce.apigateway.repository;

import reactor.core.publisher.Mono;

public interface TokenBlackListRepository {

    Mono<Boolean> containsByAccessToken(String accessToken);

}
