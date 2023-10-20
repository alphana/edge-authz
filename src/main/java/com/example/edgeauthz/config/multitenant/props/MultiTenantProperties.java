package com.example.edgeauthz.props.multitenant;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.util.List;

@ConfigurationProperties(prefix = MultiTenantProperties.PREFIX)
@Getter
@Setter
public class MultiTenantProperties {

    public static final String PREFIX = "apigateway";

    private List<Tenant> tenants;

    @Getter
    @Setter
    public static class Tenant {
        private String name;
        private TenantSecurity security;

    }

    public enum TenantResolverStrategy{
        plt_duid, plt_did , iss_realm,azp
    }
    @Getter
    @Setter
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

    @Getter
    @Setter
    public static class AuthzClient {

        private String sslRequired;
        private String verifyTokenAudience;
        private String resource;
        private Credentials credentials;
    }

    @Getter
    @Setter
    public  static class Credentials {
        private String secret;
    }
}