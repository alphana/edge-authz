package com.example.edgeauthz.authz.resolver;

import com.example.edgeauthz.TokenAttributes;
import com.example.edgeauthz.props.MultiTenantProperties;
import com.example.edgeauthz.props.multitenant.MultiTenantProperties;
import com.example.edgeauthz.props.multitenant.TenantsContext;
import lombok.Data;
import org.keycloak.adapters.authorization.PolicyEnforcer;
import org.keycloak.adapters.authorization.TokenPrincipal;
import org.keycloak.representations.adapters.config.PolicyEnforcerConfig;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class PolicyEnforcerResolver {

    private final HashMap<String, PolicyEnforcer> tenantPolicyEnforcerMap;
    private final TenantsContext tenants;


    public PolicyEnforcerResolver(TenantsContext tenants) {
        this.tenants = tenants;
        tenantPolicyEnforcerMap = new HashMap<>();
    }

    public PolicyEnforcer resolve(String tenantId) {
        return tenantPolicyEnforcerMap.computeIfAbsent(tenantId, s -> {

            PolicyEnforcerConfigResolver enforcerConfigResolver = new PolicyEnforcerConfigResolver();

            MultiTenantProperties.Tenant tenant = resolveTenant(tenantId);

            MultiTenantProperties.ResourceServer resourceServerConfig = tenant.getSecurity().getResourceServer();
            PolicyEnforcerConfig enforcerConfig = enforcerConfigResolver.resolve(resourceServerConfig).getEnforcerConfig();

            PolicyEnforcer result = PolicyEnforcer.builder()
                    .authServerUrl(enforcerConfig.getAuthServerUrl())
                    .realm(enforcerConfig.getRealm())
                    .clientId(enforcerConfig.getResource())
                    .credentials(enforcerConfig.getCredentials())
                    .bearerOnly(false)
                    .enforcerConfig(enforcerConfig)
                    .build();

            tenantPolicyEnforcerMap.put(tenantId, result);

            return result;
        });
    }


    public PolicyEnforcer resolve(TokenPrincipal token) {
        String tenantId=tenants.getTenant(token).getTenantId();
        return tenantPolicyEnforcerMap.computeIfAbsent(tenantId,s -> {});


    }



}
