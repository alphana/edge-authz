package com.example.edgeauthz.props.multitenant;


import com.example.edgeauthz.TokenAttributes;
import jakarta.annotation.PostConstruct;
import org.keycloak.adapters.authorization.TokenPrincipal;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.BiFunction;

@Component
public class TenantsContext {
    private final MultiTenantProperties tenants;
    private final Map<String, TenantContext> tenantsMap;

    private BiFunction<TokenPrincipal, MultiTenantProperties.Tenant, Boolean> domainIDMatcher = (token, tenant) -> {
        var tokenValue = token.getToken().getOtherClaims().getOrDefault(TokenAttributes.DOMAIN_ID, "nill").toString();
        return tokenValue.equals(tenant.getName());
    };

    private BiFunction<TokenPrincipal, MultiTenantProperties.Tenant, Boolean> domainUUIDMatcher = (token, tenant) -> {
        String tokenValue = token.getToken().getOtherClaims().getOrDefault(TokenAttributes.DOMAIN_UUID, "nill").toString();
        return tokenValue.equals(tenant.getName());
    };

    private BiFunction<TokenPrincipal, MultiTenantProperties.Tenant, Boolean> azpMatcher = (token, tenant) -> {
        String azp = token.getToken().getOtherClaims().getOrDefault("azp", "nill").toString();
        String realm = token.getToken().getIssuer().substring(token.getToken().getIssuer().lastIndexOf("/") + 1);
        return realm.equals(tenant.getSecurity().getRealm()) && azp.equals(tenant.getSecurity().getAuthorizedParty());
    };

    private BiFunction<TokenPrincipal, MultiTenantProperties.Tenant, Boolean> realmMatcher = (token, tenant) -> {
        String realm = token.getToken().getIssuer().substring(token.getToken().getIssuer().lastIndexOf("/") + 1);
        return realm.equals(tenant.getSecurity().getRealm());
    };

    public TenantsContext(MultiTenantProperties tenants) {
        this.tenants = tenants;
        this.tenantsMap = new HashMap<>();
    }

    @PostConstruct
    private void populateTenantsContext() {
        tenants.getTenants().forEach(tenant -> {
            switch (tenant.getSecurity().getResolverstrategy()) {
                case plt_did -> tenantsMap.put(tenant.getName(), new TenantContext(domainIDMatcher, tenant));
                case plt_duid -> tenantsMap.put(tenant.getName(), new TenantContext(domainUUIDMatcher, tenant));
                case azp -> tenantsMap.put(tenant.getName(), new TenantContext(azpMatcher, tenant));
                case iss_realm -> tenantsMap.put(tenant.getName(), new TenantContext(realmMatcher, tenant));
            }
        });
    }

    public TenantContext getTenant(TokenPrincipal token) {
        return tenantsMap.values().stream().filter(tenantContext -> {
            return tenantContext.match(token);
        })
                .findFirst()
                .orElseThrow(() -> new RuntimeException("no match exception")
        );
    }

    private static class TenantContext {
        BiFunction<TokenPrincipal, MultiTenantProperties.Tenant, Boolean> claimExtractor;

        MultiTenantProperties.Tenant tenant;

        TenantContext(BiFunction<TokenPrincipal, MultiTenantProperties.Tenant, Boolean> claimExtractor, MultiTenantProperties.Tenant tenant) {
            this.claimExtractor = claimExtractor;
            this.tenant = tenant;
        }
        public String getTenantId(){
            return tenant.getSecurity().getId();
        }
        public Boolean match(TokenPrincipal tokenPrincipal) {
            return claimExtractor.apply(tokenPrincipal, tenant);
        }


    }

}