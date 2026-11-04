package com.novawealth.gateway.token;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;

import com.novawealth.gateway.config.GatewayProperties;

import reactor.core.publisher.Mono;

/**
 * OAuth2 token endpoint for machine clients (RFC 6749 section 4.4, client credentials grant).
 * Clients authenticate with HTTP Basic (client_secret_basic) or form fields (client_secret_post)
 * and may ask for a subset of their allowed scopes. Also serves the JWKS.
 */
@RestController
public class ClientCredentialsController {

    private final GatewayProperties props;
    private final TokenService tokens;
    private final JwtKeys keys;

    public ClientCredentialsController(GatewayProperties props, TokenService tokens, JwtKeys keys) {
        this.props = props;
        this.tokens = tokens;
        this.keys = keys;
    }

    @GetMapping(value = "/.well-known/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> jwks() {
        return keys.publicJwkSet().toJSONObject();
    }

    @PostMapping(value = "/oauth2/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
                 produces = MediaType.APPLICATION_JSON_VALUE)
    public Mono<ResponseEntity<Map<String, Object>>> token(ServerWebExchange exchange,
                                                          @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        return exchange.getFormData().map(form -> issue(form, authorization));
    }

    ResponseEntity<Map<String, Object>> issue(MultiValueMap<String, String> form, String authorization) {
        if (!"client_credentials".equals(form.getFirst("grant_type"))) {
            return error(HttpStatus.BAD_REQUEST, "unsupported_grant_type", "Only client_credentials is supported");
        }
        String[] credentials = basicCredentials(authorization)
                .orElse(new String[] {form.getFirst("client_id"), form.getFirst("client_secret")});
        Optional<GatewayProperties.Client> client = authenticate(credentials[0], credentials[1]);
        if (client.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .header(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"novawealth\"")
                    .body(Map.of("error", "invalid_client"));
        }

        List<String> allowed = client.get().scopes();
        String requested = form.getFirst("scope");
        List<String> granted = (requested == null || requested.isBlank())
                ? allowed
                : Arrays.stream(requested.trim().split("\\s+")).distinct().toList();
        if (!allowed.containsAll(granted)) {
            return error(HttpStatus.BAD_REQUEST, "invalid_scope", "Client may request only: " + String.join(" ", allowed));
        }

        TokenService.IssuedToken token = tokens.forClient(client.get().clientId(), granted);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("access_token", token.value());
        body.put("token_type", "Bearer");
        body.put("expires_in", token.expiresInSeconds());
        body.put("scope", token.scope());
        return ResponseEntity.ok()
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .body(body);
    }

    private Optional<GatewayProperties.Client> authenticate(String id, String secret) {
        if (id == null || secret == null) return Optional.empty();
        return props.clients().stream()
                .filter(c -> c.clientId().equals(id))
                .filter(c -> MessageDigest.isEqual(c.clientSecret().getBytes(StandardCharsets.UTF_8),
                        secret.getBytes(StandardCharsets.UTF_8)))
                .findFirst();
    }

    private static Optional<String[]> basicCredentials(String header) {
        if (header == null || !header.regionMatches(true, 0, "Basic ", 0, 6)) return Optional.empty();
        try {
            String decoded = new String(Base64.getDecoder().decode(header.substring(6).trim()), StandardCharsets.UTF_8);
            int colon = decoded.indexOf(':');
            if (colon < 0) return Optional.empty();
            // RFC 6749 2.3.1: id and secret are form-url-encoded before Base64
            return Optional.of(new String[] {
                    java.net.URLDecoder.decode(decoded.substring(0, colon), StandardCharsets.UTF_8),
                    java.net.URLDecoder.decode(decoded.substring(colon + 1), StandardCharsets.UTF_8)});
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    private static ResponseEntity<Map<String, Object>> error(HttpStatus status, String code, String description) {
        return ResponseEntity.status(status).body(Map.of("error", code, "error_description", description));
    }
}
