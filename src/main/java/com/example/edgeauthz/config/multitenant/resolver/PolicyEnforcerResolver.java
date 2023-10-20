package com.example.edgeauthz.config.multitenant.resolver;

import com.example.edgeauthz.config.multitenant.resolver.PolicyEnforcerConfigResolver;
import com.example.edgeauthz.config.multitenant.resolver.TenantsResolver;
import org.keycloak.adapters.authorization.PolicyEnforcer;
import org.keycloak.adapters.authorization.TokenPrincipal;
import org.keycloak.representations.adapters.config.PolicyEnforcerConfig;
import org.springframework.stereotype.Component;

import java.util.HashMap;

@Component
public class PolicyEnforcerResolver {

    private final HashMap<String, PolicyEnforcer> tenantPolicyEnforcerMap;
    private final TenantsResolver tenants;
    private final PolicyEnforcerConfigResolver enforcerConfigResolver;

    public PolicyEnforcerResolver(TenantsResolver tenants) {
        this.tenants = tenants;
        tenantPolicyEnforcerMap = new HashMap<>();
        enforcerConfigResolver = new PolicyEnforcerConfigResolver(tenants);
    }



    public PolicyEnforcer resolve(TokenPrincipal token) {
        String tenantName=tenants.getMatchingTenant(token).getName();
        return tenantPolicyEnforcerMap.computeIfAbsent(tenantName,newTenantName -> {

            PolicyEnforcerConfig enforcerConfig= enforcerConfigResolver.resolve(newTenantName);

            return PolicyEnforcer.builder()
                    .authServerUrl(enforcerConfig.getAuthServerUrl())
                    .realm(enforcerConfig.getRealm())
                    .clientId(enforcerConfig.getResource())
                    .credentials(enforcerConfig.getCredentials())
                    .bearerOnly(false)
                    .enforcerConfig(enforcerConfig)
                    .build();

        });


    }



}
