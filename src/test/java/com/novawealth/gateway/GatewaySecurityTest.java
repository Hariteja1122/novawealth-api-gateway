package com.novawealth.gateway;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.function.BodyInserters;

/** Boots the real gateway (no downstream services or Redis needed for these paths). */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class GatewaySecurityTest {

    @Autowired WebTestClient web;

    @Test
    void jwksIsPublic() {
        web.get().uri("/.well-known/jwks.json").exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.keys[0].kty").isEqualTo("RSA")
                .jsonPath("$.keys[0].d").doesNotExist();
    }

    @Test
    void apiWithoutTokenIs401() {
        web.get().uri("/api/portfolios").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void clientCredentialsTokenEndpointWorksEndToEnd() {
        web.post().uri("/oauth2/token")
                .headers(h -> h.setBasicAuth("back-office-batch", "back-office-secret"))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData("grant_type", "client_credentials"))
                .exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.token_type").isEqualTo("Bearer");
    }
}
