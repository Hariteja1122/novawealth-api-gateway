# novawealth-api-gateway

Edge for NovaWealth (Spring Cloud Gateway, WebFlux). Port 8080.

* Routes: `/api/market/**` and `/soap/**` to market-data, `/api/insights/**` to insights, `/api/**` and `/ws/**` (WebSocket) to portfolio
* `POST /auth/login`, `/auth/register`: password check delegated to portfolio-service, gateway signs an RS256 JWT (uid, name, roles, scope)
* `POST /oauth2/token`: OAuth2 client credentials grant (client_secret_basic or client_secret_post), scope subset checks, RFC 6749 errors
* `GET /.well-known/jwks.json`: public key for every service's JWT validation
* Redis token bucket rate limiter per caller (20 rps, burst 40), CORS, `X-Correlation-Id` on every routed request

Registered clients are in `application.yml` (`novawealth.clients`), secrets from environment variables.

```bash
mvn spring-boot:run      # needs Redis
mvn verify
```
