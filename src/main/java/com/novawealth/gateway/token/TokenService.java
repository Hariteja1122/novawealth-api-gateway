package com.novawealth.gateway.token;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import com.novawealth.gateway.config.GatewayProperties;

/**
 * Mints the two kinds of access token:
 *   user tokens   sub=email, uid, name, roles, scope from the role
 *   client tokens sub=client id, scope = granted subset, no uid (cannot act as a customer)
 */
@Service
public class TokenService {

    static final List<String> USER_SCOPES = List.of("portfolio.read", "portfolio.write", "market.read", "insights.read", "insights.write");
    static final List<String> ADMIN_SCOPES = List.of("portfolio.read", "portfolio.write", "market.read", "insights.read", "insights.write", "admin");

    public record IssuedToken(String value, long expiresInSeconds, String scope) {}

    private final JwtEncoder encoder;
    private final JwtKeys keys;
    private final GatewayProperties props;

    public TokenService(JwtEncoder encoder, JwtKeys keys, GatewayProperties props) {
        this.encoder = encoder;
        this.keys = keys;
        this.props = props;
    }

    public IssuedToken forUser(Long userId, String email, String name, String role) {
        List<String> scopes = "ADMIN".equals(role) ? ADMIN_SCOPES : USER_SCOPES;
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(props.issuer())
                .subject(email)
                .audience(List.of("novawealth-api"))
                .issuedAt(now)
                .expiresAt(now.plus(props.userTokenTtl()))
                .id(UUID.randomUUID().toString())
                .claim("uid", userId)
                .claim("name", name)
                .claim("roles", List.of(role))
                .claim("scope", String.join(" ", scopes))
                .build();
        return new IssuedToken(sign(claims), props.userTokenTtl().toSeconds(), String.join(" ", scopes));
    }

    public IssuedToken forClient(String clientId, List<String> scopes) {
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(props.issuer())
                .subject(clientId)
                .audience(List.of("novawealth-api"))
                .issuedAt(now)
                .expiresAt(now.plus(props.clientTokenTtl()))
                .id(UUID.randomUUID().toString())
                .claim("client_id", clientId)
                .claim("scope", String.join(" ", scopes))
                .build();
        return new IssuedToken(sign(claims), props.clientTokenTtl().toSeconds(), String.join(" ", scopes));
    }

    private String sign(JwtClaimsSet claims) {
        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).keyId(keys.keyId()).build();
        return encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }
}
