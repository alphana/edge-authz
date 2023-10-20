package com.example.edgeauthz.config.multitenant.resolver;


import com.example.edgeauthz.TokenAttributes;
import com.example.edgeauthz.config.multitenant.props.MultiTenantProperties;
import jakarta.annotation.PostConstruct;
import org.keycloak.adapters.authorization.TokenPrincipal;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiPredicate;
import java.util.function.Function;

@Component
public class TenantsResolver {
    private final MultiTenantProperties tenants;
    private final List<TenantContext> tenantsList;



    private final BiPredicate<TokenPrincipal, MultiTenantProperties.Tenant> domainIDMatcher = (token, tenant) -> {
        var tokenValue = token.getToken().getOtherClaims().getOrDefault(TokenAttributes.DOMAIN_ID, "nill").toString();
        return tokenValue.equals(tenant.getName());
    };

    private final BiPredicate<TokenPrincipal, MultiTenantProperties.Tenant> domainUUIDMatcher = (token, tenant) -> {
        String tokenValue = token.getToken().getOtherClaims().getOrDefault(TokenAttributes.DOMAIN_UUID, "nill").toString();
        return tokenValue.equals(tenant.getName());
    };

    private final BiPredicate<TokenPrincipal, MultiTenantProperties.Tenant> azpMatcher = (token, tenant) -> {
        String azp = token.getToken().getIssuedFor();
        String realm = token.getToken().getIssuer().substring(token.getToken().getIssuer().lastIndexOf("/") + 1);
        return realm.equals(tenant.getSecurity().getRealm()) && azp.equals(tenant.getSecurity().getAuthorizedParty());
    };

    private final BiPredicate<TokenPrincipal, MultiTenantProperties.Tenant> realmMatcher = (token, tenant) -> {
        String realm = token.getToken().getIssuer().substring(token.getToken().getIssuer().lastIndexOf("/") + 1);
        return realm.equals(tenant.getSecurity().getRealm());
    };

    public TenantsResolver(MultiTenantProperties tenants) {
        this.tenants = tenants;
        this.tenantsList = new ArrayList<>();
    }

    @PostConstruct
    private void populateTenantsContext() {
        tenants.getTenants().forEach(tenant -> {
            switch (tenant.getSecurity().getResolverstrategy()) {
                case plt_did -> tenantsList.add(new TenantContext(tenant, domainIDMatcher));
                case plt_duid -> tenantsList.add(new TenantContext(tenant, domainUUIDMatcher));
                case azp -> tenantsList.add(new TenantContext(tenant, azpMatcher));
                case iss_realm -> tenantsList.add(new TenantContext(tenant, realmMatcher));
            }
        });
    }

    public TenantContext getMatchingTenant(TokenPrincipal token) {
        return tenantsList.stream()
                .filter(tenantContext -> tenantContext.match(token))
                .findFirst()
                .orElseThrow(() -> new RuntimeException("no match exception")
                );
    }

    public TenantContext getTenant(String name) {
        return tenantsList.stream()
                .filter(tenantContext -> tenantContext.getName().equals(name))
                .findFirst()
                .orElseThrow(() -> new RuntimeException("no match exception")
                );
    }

    public Map<String, Mono<ReactiveAuthenticationManager>> populateAuthenticationManager(Function<String, ReactiveJwtDecoder> decoderProvider) {
        Map<String, Mono<ReactiveAuthenticationManager>> authenticationManagers =
                new HashMap<>();
        for (TenantContext tenant : tenantsList) {
            if (authenticationManagers.put(tenant.getIssuer(), Mono.justOrEmpty(new JwtReactiveAuthenticationManager(decoderProvider.apply(tenant.getIssuer())))) != null) {
                throw new IllegalStateException("Duplicate key");
            }
        }


        return authenticationManagers;
    }

    public static class TenantContext {
        BiPredicate<TokenPrincipal, MultiTenantProperties.Tenant> claimExtractor;

        MultiTenantProperties.Tenant tenant;

        TenantContext(MultiTenantProperties.Tenant tenant, BiPredicate<TokenPrincipal, MultiTenantProperties.Tenant> claimExtractor) {
            this.claimExtractor = claimExtractor;
            this.tenant = tenant;
        }


        public String getName() {
            return tenant.getName();
        }

        public MultiTenantProperties.Tenant getTenant() {
            return tenant;
        }

        public Boolean match(TokenPrincipal tokenPrincipal) {
            return claimExtractor.test(tokenPrincipal, tenant);
        }


        public String getAuthServerUrl() {
            return tenant.getSecurity().getAuthServerUrl();
        }

        public String getRealm() {
            return tenant.getSecurity().getRealm();
        }

        public String getAuthZClient() {
            return tenant.getSecurity().getResourceServer().getAuthzClient().getResource();
        }

        public Map<String, Object> getAuthZClientCredentialsAsMap() {
            return Map.of("secret", tenant.getSecurity().getResourceServer().getAuthzClient().getCredentials().getSecret());
        }

        /**
         * if the issuer specified with the environment returns issuer or else resolves issuer using AuthServerUrl and Bean information provided
         *
         * @return issuer
         */
        public String getIssuer() {

            if (tenant.getSecurity().getIssuer() != null) return tenant.getSecurity().getIssuer();
            if (tenant.getSecurity().getAuthServerUrl() == null || tenant.getSecurity().getRealm() == null) {
                // TODO: Handle exception & print meaningful guidance
                throw new IllegalStateException("Additional information required");
            }
            return tenant.getSecurity().getAuthServerUrl() + "realms/" + tenant.getSecurity().getRealm();

        }

    }

}