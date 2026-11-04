package com.novawealth.gateway.token;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import com.novawealth.gateway.config.GatewayProperties;

class ClientCredentialsControllerTest {

    private final ClientCredentialsController controller;

    ClientCredentialsControllerTest() throws Exception {
        JwtKeys keys = new JwtKeys();
        GatewayProperties props = new GatewayProperties("http://p", "http://m", "http://i", "k", "iss",
                Duration.ofMinutes(60), Duration.ofMinutes(15), List.of(), null,
                List.of(new GatewayProperties.Client("batch", "s3cret", List.of("market.read"))));
        controller = new ClientCredentialsController(props, new TokenService(keys.jwtEncoder(), keys, props), keys);
    }

    private static MultiValueMap<String, String> form(String... kv) {
        MultiValueMap<String, String> m = new LinkedMultiValueMap<>();
        for (int i = 0; i < kv.length; i += 2) m.add(kv[i], kv[i + 1]);
        return m;
    }

    private static String basic(String id, String secret) {
        return "Basic " + Base64.getEncoder().encodeToString((id + ":" + secret).getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void issuesTokenForValidBasicCredentials() {
        var response = controller.issue(form("grant_type", "client_credentials"), basic("batch", "s3cret"));
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsEntry("token_type", "Bearer").containsEntry("scope", "market.read");
        assertThat(response.getBody().get("access_token")).asString().isNotBlank();
    }

    @Test
    void acceptsClientSecretPost() {
        var response = controller.issue(form("grant_type", "client_credentials", "client_id", "batch", "client_secret", "s3cret"), null);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void wrongSecretIsInvalidClient() {
        var response = controller.issue(form("grant_type", "client_credentials"), basic("batch", "nope"));
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).containsEntry("error", "invalid_client");
    }

    @Test
    void scopeOutsideAllowedSetIsRejected() {
        var response = controller.issue(form("grant_type", "client_credentials", "scope", "market.read admin"), basic("batch", "s3cret"));
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).containsEntry("error", "invalid_scope");
    }

    @Test
    void onlyClientCredentialsGrantIsSupported() {
        var response = controller.issue(form("grant_type", "password"), basic("batch", "s3cret"));
        assertThat(response.getBody()).containsEntry("error", "unsupported_grant_type");
    }
}
