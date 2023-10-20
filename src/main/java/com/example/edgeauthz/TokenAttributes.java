package com.example.ottheredge.policyenforcer;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public final class TokenAttributes {
    public static final String ENCRYPTED_DATA = "plt_ed";
    public static final String DOMAIN_ID = "plt_did";
    public static final String DOMAIN_UUID = "plt_duid";
    public static final String INSTITUTION_UNIT = "plt_iu";
    public static final String USER_ID = "plt_uid";
    public static final String USER_UUID = "plt_uuid";
    public static final String EMPLOYEE_ID = "plt_ei";
    public static final String DEPARTMENT_CODE = "plt_depc";
    public static final String DEPARTMENT_TYPE_CODE = "plt_deptc";
    public static final String DOMAIN_NAME = "plt_dn";
    public static final String DOMAIN_TYPE_CODE = "plt_dtc";
    public static final String USER_ROLES = "userRoles";
    public static final String DEVICE_ID = "deviceId";
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String USERNAME = "plt_un";
    public static final String SUB = "sub";
    public static final String CLIENT_ID = "plt_cid";
    public static final String USER_TYPE = "plt_ut";
    public static final String USER_IDENTIFIER = "plt_uide";
    public static final String FLOW_CLAIM_CONSTANT = "ftyp";
    public static final String RELATED_IDENTITY = "plt_ri";
    public static final String ISS = "iss";

    public static final String TOKEN_ISSUER_URL_PREFIX = "/realms";
    public static final int REALM_INDEX_PREFIX = 8;
    public static final int TOKEN_PROVIDER_INDEX_PREFIX = 1;
    public static final String PREFERRED_NAME = "preferred_username";

    private TokenAttributes() {
        // hide public ctor
    }

    public static Long getLong(Map<String, Object> claims, String claimKey) {
        if (claims.get(claimKey) != null) {
            return Long.parseLong(claims.get(claimKey).toString());
        }
        return null;
    }

    public static String getString(Map<String, Object> claims, String claimKey) {
        return (String) claims.get(claimKey);
    }

    public static List<String> getList(Map<String, Object> claims, String claimKey) {
        return claims.get(claimKey) != null ? (List<String>) claims.get(claimKey) : Collections.emptyList();
    }

    public static byte[] getByte(Map<String, Object> claims, String claimKey) {
        Object claimValue = claims.get(claimKey);
        return String.valueOf(claimValue).getBytes(StandardCharsets.UTF_8);
    }
}