package com.example.edgeauthz.config.multitenant.filter;

import com.example.edgeauthz.config.multitenant.authz.WebFluxHttpFacede;
import com.example.edgeauthz.config.multitenant.resolver.PolicyEnforcerResolver;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.keycloak.AuthorizationContext;
import org.keycloak.adapters.authorization.PolicyEnforcer;
import org.keycloak.adapters.authorization.TokenPrincipal;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.util.annotation.NonNull;

import java.nio.charset.StandardCharsets;

public class ReactiveWebServerPolicyEnforcerFilter implements WebFilter {
    private static final Log logger = LogFactory.getLog(ReactiveWebServerPolicyEnforcerFilter.class);
    private final PolicyEnforcerResolver policyEnforcerResolver;

    public ReactiveWebServerPolicyEnforcerFilter(PolicyEnforcerResolver policyEnforcerResolver) {
        this.policyEnforcerResolver = policyEnforcerResolver;
    }

    @Override
    public Mono<Void> filter(@NonNull ServerWebExchange exchange, WebFilterChain chain) {


        return ReactiveSecurityContextHolder.getContext()
                .filter((c) -> c.getAuthentication() != null)
                .map(SecurityContext::getAuthentication)
                .as((authentication) -> check(authentication,exchange) )
                .then()
                .doOnSuccess((successfulAuthz) -> logger.debug("Authorization successful"))
                .doOnError(Exception.class, ex -> handleAuthenticationFailure(exchange.getResponse(), ex) )
                .switchIfEmpty(chain.filter(exchange));

    }

    private Mono<Object> check(Mono<Authentication> authentication, ServerWebExchange exchange) {

        WebFluxHttpFacede httpFacade = new WebFluxHttpFacede(exchange);
        TokenPrincipal tokenPrinciple = httpFacade.getTokenPrincipal();

        PolicyEnforcer policyEnforcer = policyEnforcerResolver.resolve(tokenPrinciple);

        AuthorizationContext result = policyEnforcer.enforce(httpFacade.getRequest(), httpFacade.getResponse());

        if (!result.isGranted()) {
            return Mono.error(new AccessDeniedException("Access Denied"));
        }
        return Mono.empty();
    }


    private Mono<Void> handleAuthenticationFailure(ServerHttpResponse response, Exception ex) {
        if(logger.isDebugEnabled()) {
            logger.debug("Authorization failed due to : "+ ex.getMessage());
        }
        response.setRawStatusCode(HttpStatus.UNAUTHORIZED.value());
        OAuth2Error error = oauth2Error(ex);
        byte[] bytes = String.format("""
                {
                	"error_code": "%s",
                	"error_description": "%s",
                	"error_uri: "%s"
                }
                """, error.getErrorCode(), error.getDescription(), error.getUri()).getBytes(StandardCharsets.UTF_8);
        DataBuffer buffer = response.bufferFactory().wrap(bytes);
        return response.writeWith(Flux.just(buffer));
    }

    private OAuth2Error oauth2Error(Exception ex) {
        if (ex instanceof OAuth2AuthenticationException oauth2) {
            return oauth2.getError();
        }
        return new OAuth2Error(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, ex.getMessage(),
                "https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation");
    }




}