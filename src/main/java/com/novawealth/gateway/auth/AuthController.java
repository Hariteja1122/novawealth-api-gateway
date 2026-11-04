package com.novawealth.gateway.auth;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ResponseStatusException;

import com.novawealth.gateway.config.GatewayProperties;
import com.novawealth.gateway.token.TokenService;

import reactor.core.publisher.Mono;

/**
 * Customer login and sign up. The password check happens in portfolio-service (which owns
 * the users table); the gateway only signs the token. Errors from downstream are passed
 * through with their status (401 bad password, 423 locked, 409 email taken, 400 invalid).
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    public record AuthUser(Long userId, String email, String fullName, String role) {}

    public record LoginResponse(String accessToken, String tokenType, long expiresIn, String scope, AuthUser user) {}

    private final WebClient portfolio;
    private final TokenService tokens;

    public AuthController(WebClient.Builder builder, GatewayProperties props, TokenService tokens) {
        this.portfolio = builder
                .baseUrl(props.portfolioUrl())
                .defaultHeader("X-Internal-Api-Key", props.internalApiKey())
                .build();
        this.tokens = tokens;
    }

    @PostMapping(value = "/login", consumes = MediaType.APPLICATION_JSON_VALUE)
    public Mono<LoginResponse> login(@RequestBody Map<String, Object> body) {
        return call("/internal/auth/verify", body).map(this::issue);
    }

    @PostMapping(value = "/register", consumes = MediaType.APPLICATION_JSON_VALUE)
    public Mono<LoginResponse> register(@RequestBody Map<String, Object> body) {
        return call("/internal/auth/register", body).map(this::issue);
    }

    private LoginResponse issue(AuthUser user) {
        TokenService.IssuedToken token = tokens.forUser(user.userId(), user.email(), user.fullName(), user.role());
        return new LoginResponse(token.value(), "Bearer", token.expiresInSeconds(), token.scope(), user);
    }

    private Mono<AuthUser> call(String path, Map<String, Object> body) {
        return portfolio.post().uri(path)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .exchangeToMono(response -> response.statusCode().is2xxSuccessful()
                        ? response.bodyToMono(AuthUser.class)
                        : passThrough(response))
                .onErrorMap(e -> !(e instanceof ResponseStatusException),
                        e -> new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Sign in is unavailable right now", e));
    }

    @SuppressWarnings("unchecked")
    private static Mono<AuthUser> passThrough(ClientResponse response) {
        HttpStatusCode status = response.statusCode();
        return response.bodyToMono(Map.class)
                .defaultIfEmpty(Map.of())
                .flatMap(problem -> {
                    Object detail = ((Map<String, Object>) problem).getOrDefault("detail", "Request failed");
                    return Mono.error(new ResponseStatusException(status, String.valueOf(detail)));
                });
    }
}
