package com.example.edgeauthz.config.multitenant.props;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;
import java.util.Map;
@Data
@ConfigurationProperties(prefix = MultiTenantProperties.PREFIX)
public class MultiTenantProperties {

    public static final String PREFIX = "apigateway";

    private List<Tenant> tenants;

    @Data
    public static class Tenant {
        private String name;
        private TenantSecurity security;
    }

    public enum TenantResolverStrategy{
        plt_duid, plt_did , iss_realm,azp
    }
    @Data
    public static class TenantSecurity {
        private String id;
        private String tokenClaimKey;
        private TenantResolverStrategy resolverstrategy;
        private String authServerUrl;
        private String jwkSetUri;
        private String issuer;
        private ResourceServer resourceServer;
        private String authorizedParty;
        private String realm;
    }


    @Data
    public static class ResourceServer {
        private AuthzClient authzClient;
    }

    @Data
    public static class AuthzClient {
        private String sslRequired;
        private String verifyTokenAudience;
        private String resource;
        private Credentials credentials;
    }

    @Data
    public  static class Credentials {
        private String secret;
    }
}