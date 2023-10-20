package com.example.edgeauthz.config.multitenant.resolver;

import org.keycloak.representations.adapters.config.PolicyEnforcerConfig;

public class PolicyEnforcerConfigResolver {

    private final TenantsResolver tenantsResolver;

    private PolicyEnforcerConfig getEnforcerConfig(TenantsResolver.TenantContext tenant) {

        PolicyEnforcerConfig policyEnforcerConfig = new PolicyEnforcerConfig();

        policyEnforcerConfig.setAuthServerUrl(tenant.getAuthServerUrl());
        policyEnforcerConfig.setRealm(tenant.getRealm());

        policyEnforcerConfig.setResource(tenant.getAuthZClient());
        policyEnforcerConfig.setCredentials(tenant.getAuthZClientCredentialsAsMap());

        return policyEnforcerConfig;
    }

    public PolicyEnforcerConfigResolver(TenantsResolver tenantsResolver) {
        this.tenantsResolver = tenantsResolver;
    }

    public PolicyEnforcerConfig resolve(String tenantName) {
        TenantsResolver.TenantContext tenant = tenantsResolver.getTenant(tenantName);
        return getEnforcerConfig(tenant);
    }
}