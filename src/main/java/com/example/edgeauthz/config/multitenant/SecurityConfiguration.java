package com.example.edgeauthz.config.multitenant;

import com.example.edgeauthz.config.multitenant.resolver.PolicyEnforcerResolver;
import com.example.edgeauthz.config.multitenant.filter.ReactiveWebServerPolicyEnforcerFilter;
import com.example.edgeauthz.config.multitenant.resolver.TenantsResolver;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerReactiveAuthenticationManagerResolver;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.function.Function;

@Configuration
@EnableConfigurationProperties
@ConfigurationPropertiesScan(basePackages = {"com.example.edgeauthz.config.multitenant.props"})
public class SecurityConfiguration {

    public ReactiveWebServerPolicyEnforcerFilter reactiveWebServerPolicyEnforcerFilter(PolicyEnforcerResolver policyEnforcerResolver) {
        return new ReactiveWebServerPolicyEnforcerFilter(policyEnforcerResolver);
    }

    @Bean
    SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http, TenantsResolver tenantsResolver,PolicyEnforcerResolver resolver) {

        http.authorizeExchange(exchanges ->
                        exchanges.anyExchange().authenticated())
                .oauth2ResourceServer(oauth2 ->
                        oauth2.authenticationManagerResolver(jwtIssuerReactiveAuthenticationManagerResolver(tenantsResolver))
                )
                .addFilterAfter(reactiveWebServerPolicyEnforcerFilter(resolver), SecurityWebFiltersOrder.AUTHENTICATION)
        ;
        return http.build();
    }

    private JwtIssuerReactiveAuthenticationManagerResolver jwtIssuerReactiveAuthenticationManagerResolver(TenantsResolver tenantsResolver) {
        Function<String,ReactiveJwtDecoder> reactiveJwtDecoderProvider= issuer -> NimbusReactiveJwtDecoder.withIssuerLocation(issuer).build();

        Map<String, Mono<ReactiveAuthenticationManager>> authenticationManagers = tenantsResolver.populateAuthenticationManager(reactiveJwtDecoderProvider);

        return new JwtIssuerReactiveAuthenticationManagerResolver(authenticationManagers::get);
    }





}
