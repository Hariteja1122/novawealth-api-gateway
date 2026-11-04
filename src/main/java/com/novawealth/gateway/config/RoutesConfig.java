package com.novawealth.gateway.config;

import java.net.InetSocketAddress;
import java.security.Principal;
import java.util.Optional;

import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.cloud.gateway.filter.ratelimit.RedisRateLimiter;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import reactor.core.publisher.Mono;

/**
 * Routes, most specific first. Every API route goes through the Redis token bucket rate
 * limiter keyed by caller (token subject, or client IP when anonymous). Over the limit the
 * caller gets 429 with X-RateLimit-* headers; because the bucket lives in Redis the limit
 * holds across all gateway replicas.
 */
@Configuration
public class RoutesConfig {

    @Bean
    @Primary
    RedisRateLimiter redisRateLimiter(GatewayProperties props) {
        return new RedisRateLimiter(props.rateLimit().replenishRate(), props.rateLimit().burstCapacity(), 1);
    }

    @Bean
    KeyResolver callerKeyResolver() {
        return exchange -> exchange.getPrincipal()
                .map(Principal::getName)
                .switchIfEmpty(Mono.fromSupplier(() -> "ip:" + Optional.ofNullable(exchange.getRequest().getRemoteAddress())
                        .map(InetSocketAddress::getHostString)
                        .orElse("unknown")));
    }

    @Bean
    RouteLocator routes(RouteLocatorBuilder builder, GatewayProperties props,
                        RedisRateLimiter limiter, KeyResolver callerKeyResolver) {
        String portfolioWs = props.portfolioUrl().replaceFirst("^http", "ws");
        return builder.routes()
                .route("market-data", r -> r.path("/api/market/**", "/soap/**")
                        .filters(f -> f.requestRateLimiter(c -> c.setRateLimiter(limiter).setKeyResolver(callerKeyResolver)))
                        .uri(props.marketDataUrl()))
                .route("insights", r -> r.path("/api/insights/**")
                        .filters(f -> f.requestRateLimiter(c -> c.setRateLimiter(limiter).setKeyResolver(callerKeyResolver)))
                        .uri(props.insightsUrl()))
                .route("portfolio-ws", r -> r.path("/ws/**")
                        .uri(portfolioWs))
                .route("portfolio", r -> r.order(10).path("/api/**")
                        .filters(f -> f.requestRateLimiter(c -> c.setRateLimiter(limiter).setKeyResolver(callerKeyResolver)))
                        .uri(props.portfolioUrl()))
                .build();
    }
}
