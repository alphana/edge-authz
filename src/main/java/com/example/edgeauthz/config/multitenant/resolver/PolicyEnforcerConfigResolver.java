package com.example.edgeauthz.authz.resolver;

import org.keycloak.representations.adapters.config.PolicyEnforcerConfig;


import java.util.Map;

public class PolicyEnforcerConfigResolver {

    private MultiTenantProperties.ResourceServer resourceServer;




    public String getAuthServerUrl() {
        return resourceServer.getAuthServerUrl();
    }

    public String getRealm() {
        return resourceServer.getAuthzClient().getRealm();
    }

    public String getResource() {
        return resourceServer.getAuthzClient().getResource();
    }

    public Map<String, Object> getCredentials() {
        return Map.of("secret", resourceServer.getAuthzClient().getCredentials().getSecret());
    }

    public PolicyEnforcerConfig getEnforcerConfig() {
        PolicyEnforcerConfig policyEnforcerConfig = new PolicyEnforcerConfig();
        policyEnforcerConfig.setAuthServerUrl(getAuthServerUrl());
        policyEnforcerConfig.setRealm(getRealm());
        policyEnforcerConfig.setResource(getResource());
        policyEnforcerConfig.setCredentials(getCredentials());
        return policyEnforcerConfig;
    }

    public PolicyEnforcerConfigResolver resolve(MultiTenantProperties.ResourceServer resourceServer) {
        this.resourceServer=resourceServer;
        return this;
    }
}