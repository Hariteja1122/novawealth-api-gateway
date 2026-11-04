package com.novawealth.gateway.config;

import java.time.Duration;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * @param portfolioUrl    portfolio-service base URL (also used for /ws, converted to ws://)
 * @param marketDataUrl   market-data-service base URL
 * @param insightsUrl     insights-service base URL
 * @param internalApiKey  key sent on /internal/** calls to portfolio-service
 * @param issuer          "iss" claim on every token
 * @param userTokenTtl    lifetime of tokens issued at login
 * @param clientTokenTtl  lifetime of client credentials tokens
 * @param corsOrigins     browser origins allowed to call the API directly
 * @param rateLimit       requests per second per caller, and the burst allowance
 * @param clients         registered OAuth2 clients for the client credentials grant
 */
@ConfigurationProperties(prefix = "novawealth")
public record GatewayProperties(
        String portfolioUrl,
        String marketDataUrl,
        String insightsUrl,
        String internalApiKey,
        String issuer,
        Duration userTokenTtl,
        Duration clientTokenTtl,
        List<String> corsOrigins,
        RateLimit rateLimit,
        List<Client> clients) {

    public GatewayProperties {
        if (issuer == null) issuer = "https://novawealth.local";
        if (userTokenTtl == null) userTokenTtl = Duration.ofMinutes(60);
        if (clientTokenTtl == null) clientTokenTtl = Duration.ofMinutes(15);
        if (corsOrigins == null) corsOrigins = List.of();
        if (rateLimit == null) rateLimit = new RateLimit(20, 40);
        if (clients == null) clients = List.of();
    }

    public record RateLimit(int replenishRate, int burstCapacity) {}

    public record Client(String clientId, String clientSecret, List<String> scopes) {}
}
