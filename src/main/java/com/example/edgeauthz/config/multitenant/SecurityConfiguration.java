package com.example.edgeauthz.config;

import com.example.edgeauthz.authz.resolver.PolicyEnforcerResolver;
import com.example.edgeauthz.filter.ReactiveWebServerPolicyEnforcerFilter;
import com.example.edgeauthz.props.multitenant.MultiTenantProperties;
import com.example.edgeauthz.props.multitenant.TenantsContext;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerReactiveAuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.HashMap;
import java.util.Map;

@Configuration
@EnableConfigurationProperties
@ConfigurationPropertiesScan(basePackages = {"com.example.edgeauthz.props"})
public class SecurityConfiguration {

    final MultiTenantProperties tenantProperties;

    public SecurityConfiguration(MultiTenantProperties tenantProperties) {
        this.tenantProperties = tenantProperties;
    }

    public ReactiveWebServerPolicyEnforcerFilter reactiveWebServerPolicyEnforcerFilter(PolicyEnforcerResolver policyEnforcerResolver) {
        return new ReactiveWebServerPolicyEnforcerFilter(policyEnforcerResolver);
    }

    @Bean
    SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http, PolicyEnforcerResolver resolver) {

        http.authorizeExchange(exchanges ->
                        exchanges.anyExchange().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2.authenticationManagerResolver(jwtIssuerReactiveAuthenticationManagerResolver()))
                .addFilterAt(reactiveWebServerPolicyEnforcerFilter(resolver), SecurityWebFiltersOrder.AUTHORIZATION)
        ;
        return http.build();
    }

    private JwtIssuerReactiveAuthenticationManagerResolver jwtIssuerReactiveAuthenticationManagerResolver() {
        Map<String, Mono<ReactiveAuthenticationManager>> authenticationManagers = new HashMap<>();

        tenantProperties.getTenants().forEach(tenant -> {
            String issuer=tenant.getSecurity().getIssuer();
            authenticationManagers.put(issuer, Mono.justOrEmpty(new JwtReactiveAuthenticationManager(newDecoder(issuer))));
        });

        return new JwtIssuerReactiveAuthenticationManagerResolver(authenticationManagers::get);
    }

    private ReactiveJwtDecoder newDecoder(String issuer) {
        return NimbusReactiveJwtDecoder.withIssuerLocation(issuer).build();
    }



    @Bean
    PolicyEnforcerResolver policyEnforcerResolver() {
        return new PolicyEnforcerResolver(tenantProperties);
    }

    @Bean
    TenantsContext tenantsContext() {
        return new TenantsContext(tenantProperties);
    }
}
