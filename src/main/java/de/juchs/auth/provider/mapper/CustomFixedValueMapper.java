package de.juchs.auth.provider.mapper;

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CustomFixedValueMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper,
        OIDCIDTokenMapper, UserInfoTokenMapper {

    public static final String PROVIDER_ID = "custom-fixed-value-mapper";
    private static final String PREFIX_CONFIG = "claim.prefix";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, CustomFixedValueMapper.class);
        ProviderConfigProperty prefixProperty = new ProviderConfigProperty();
        prefixProperty.setName(PREFIX_CONFIG);
        prefixProperty.setLabel("Claim Prefix");
        prefixProperty.setType(ProviderConfigProperty.STRING_TYPE);
        prefixProperty.setHelpText("Prefix to be added to the claims from the other application.");
        configProperties.add(prefixProperty);
    }

    @Override
    public String getDisplayCategory() {
        return "Token Mapper";
    }

    @Override
    public String getDisplayType() {
        return "Custom Token Mapper";
    }

    @Override
    public String getHelpText() {
        return "Just a random mapper";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel,
                            UserSessionModel userSession, KeycloakSession keycloakSession,
                            ClientSessionContext clientSessionCtx) {
        String prefix = mappingModel.getConfig().getOrDefault(PREFIX_CONFIG, "");
        Map<String, String> otherClaims = getClaimsFromOtherApplication();
        for (Map.Entry<String, String> entry : otherClaims.entrySet()) {
            String claimName = entry.getKey();
            String claimValue = entry.getValue();
            token.getOtherClaims().put(prefix + claimName, claimValue);
        }
    }

    // Static method to return claims for testing purposes
    private static Map<String, String> getClaimsFromOtherApplication() {
        Map<String, String> claims = new HashMap<>();
        claims.put("username", "jubol92");
        claims.put("age", "32");
        claims.put("birthyear", "1992");
        return claims;
    }
}