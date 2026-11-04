package com.novawealth.gateway.token;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import com.novawealth.gateway.config.GatewayProperties;

class TokenServiceTest {

    private final JwtKeys keys = newKeys();
    private final GatewayProperties props = new GatewayProperties("http://p", "http://m", "http://i", "k",
            "https://novawealth.test", Duration.ofMinutes(60), Duration.ofMinutes(15), List.of(), null, List.of());
    private final TokenService tokens = new TokenService(keys.jwtEncoder(), keys, props);

    @Test
    void userTokenCarriesIdentityRolesAndScopes() throws Exception {
        TokenService.IssuedToken token = tokens.forUser(7L, "john.carter@example.com", "John Carter", "USER");
        Jwt jwt = keys.reactiveJwtDecoder().decode(token.value()).block();

        assertThat(jwt.getSubject()).isEqualTo("john.carter@example.com");
        assertThat(((Number) jwt.getClaim("uid")).longValue()).isEqualTo(7L);
        assertThat(jwt.getClaimAsStringList("roles")).containsExactly("USER");
        assertThat(jwt.getClaimAsString("scope")).contains("portfolio.write").doesNotContain("admin");
        assertThat(jwt.getHeaders().get("kid")).isEqualTo(keys.keyId());
        assertThat(token.expiresInSeconds()).isEqualTo(3600);
    }

    @Test
    void adminTokenGetsAdminScope() throws Exception {
        Jwt jwt = keys.reactiveJwtDecoder().decode(tokens.forUser(1L, "admin@novawealth.dev", "Ops", "ADMIN").value()).block();
        assertThat(jwt.getClaimAsString("scope")).contains("admin");
    }

    @Test
    void clientTokenHasNoUserIdentity() throws Exception {
        Jwt jwt = keys.reactiveJwtDecoder().decode(tokens.forClient("portfolio-service", List.of("market.read")).value()).block();
        assertThat(jwt.getClaims()).doesNotContainKey("uid");
        assertThat(jwt.getClaimAsString("scope")).isEqualTo("market.read");
    }

    @Test
    void jwksPublishesOnlyThePublicKey() {
        assertThat(keys.publicJwkSet().getKeys()).singleElement().satisfies(k -> assertThat(k.isPrivate()).isFalse());
    }

    private static JwtKeys newKeys() {
        try {
            return new JwtKeys();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
