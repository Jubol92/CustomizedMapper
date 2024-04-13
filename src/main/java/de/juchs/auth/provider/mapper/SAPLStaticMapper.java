package de.juchs.auth.provider.mapper;

import jakarta.ws.rs.core.HttpHeaders;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import java.util.*;

public class SAPLStaticMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper,
        OIDCIDTokenMapper, UserInfoTokenMapper {

    public static final String PROVIDER_ID = "demo-sapl-mapper";
    private static final String PREFIX_CONFIG = "claim.prefix";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, SAPLStaticMapper.class);
        ProviderConfigProperty prefixProperty = new ProviderConfigProperty();
        prefixProperty.setName(PREFIX_CONFIG);

        // Sets a prefix like SAPL in the token claim
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
        return "Demo SAPL Mapper";
    }

    @Override
    public String getHelpText() {
        return "Demo mapper to add static content to a claim";
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

        // Just a list of random token claims
        claims.put("username", "jubol92");
        claims.put("age", "32");
        claims.put("birthyear", "1992");
        return claims;
    }

    @Override
    public AccessToken transformAccessToken(
            AccessToken token,
            ProtocolMapperModel mappingModel,
            KeycloakSession keycloakSession,
            UserSessionModel userSession,
            ClientSessionContext clientSessionCtx) {

        Map<String, Object> claims = token.getOtherClaims();
        Map<String, String> headerClaims = getClaimsFromHeader(keycloakSession.getContext().getRequestHeaders());
        claims.putAll(headerClaims);

        setClaim(token, mappingModel, userSession, keycloakSession, clientSessionCtx);
        return token;
    }

    // Method to extract claims from the request header
    private Map<String, String> getClaimsFromHeader(HttpHeaders httpHeaders) {
        Map<String, String> claims = new HashMap<>();
        // List of tuples containing prefixes and corresponding claim names
        List<Map.Entry<String, String>> prefixClaimPairs = Arrays.asList(
                tuple("action", "action"),
                tuple("subject", "subject")
        );
        for (Map.Entry<String, String> pair : prefixClaimPairs) {
            String prefix = pair.getKey();
            String claimName = pair.getValue();
            for (String headerName : httpHeaders.getRequestHeaders().keySet()) {
                // Check if the header name starts with the current prefix
                if (headerName.startsWith(prefix)) {
                    List<String> headerValues = httpHeaders.getRequestHeader(headerName);
                    if (headerValues != null && !headerValues.isEmpty()) {
                        // Use the corresponding claim name for this prefix
                        String claimValue = headerValues.get(0); // Assuming only one value per claim
                        claims.put(claimName, claimValue);
                    }
                }
            }
        }
        return claims;
    }

    // Method to create a tuple of two values
    private static <L, R> Map.Entry<L, R> tuple(L left, R right) {
        return new AbstractMap.SimpleEntry<>(left, right);
    }
}