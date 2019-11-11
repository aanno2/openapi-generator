package org.openapitools.codegen;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.swagger.v3.oas.models.security.OAuthFlow;
import io.swagger.v3.oas.models.security.Scopes;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

public class OpenIdConnect {

    private static final ObjectMapper mapper = new ObjectMapper();

    private final DefaultCodegen codegen;

    private final URL discovery;

    private JsonNode rootNode;

    // https://stackoverflow.com/questions/28658735/what-are-keycloaks-oauth2-openid-connect-endpoints
    private Set<String> grantTypes = new HashSet<>();
    private Set<String> responseTypes = new HashSet<>();
    private Set<String> claims = new HashSet<>();
    private Set<String> scopes = new HashSet<>();

    private String authorizationUrl;
    private String tokenUrl;

    public OpenIdConnect(DefaultCodegen codegen, String url) throws MalformedURLException {
        this.codegen = codegen;
        this.discovery = new URL(url);
    }

    public OpenIdConnect retrieve() throws IOException {
        if (rootNode == null) {
            rootNode = mapper.readTree(discovery);
            authorizationUrl = rootNode.get("authorization_endpoint").asText();
            tokenUrl = rootNode.get("token_endpoint").asText();
            JsonNode grantArray = rootNode.get("grant_types_supported");
            if (grantArray.isArray()) {
                for (JsonNode el: grantArray) {
                    grantTypes.add(el.asText());
                }
            }
            JsonNode responseArray = rootNode.get("response_types_supported");
            if (responseArray.isArray()) {
                for (JsonNode el: responseArray) {
                    responseTypes.add(el.asText());
                }
            }
            JsonNode claimArray = rootNode.get("claims_supported");
            if (claimArray.isArray()) {
                for (JsonNode el: claimArray) {
                    claims.add(el.asText());
                }
            }
            JsonNode scopeArray = rootNode.get("scopes_supported");
            if (scopeArray.isArray()) {
                for (JsonNode el: scopeArray) {
                    scopes.add(el.asText());
                }
            }
        }
        return this;
    }

    public void addToSecurity(CodegenSecurity cs) {
        // cs.name = "openIdConnect";
        cs.isKeyInHeader = cs.isKeyInQuery = cs.isKeyInCookie = cs.isApiKey = cs.isBasic = false;
        cs.isOpenIdConnect = true;
        cs.isOAuth = true;
        cs.authorizationUrl = authorizationUrl;
        cs.tokenUrl = tokenUrl;
        cs.hasScopes = !scopes.isEmpty();

        Scopes flowScopes = new Scopes();
        for (String s: scopes) {
            // we have no description
            flowScopes.addString(s, s);
        }
        OAuthFlow flow = new OAuthFlow();
        flow = flow.authorizationUrl(authorizationUrl).tokenUrl(tokenUrl).scopes(flowScopes);
        // cs.scopes = ;

        if (grantTypes.isEmpty()) {
            throw new RuntimeException("missing oauth flow in " + cs.name);
        }
        // Can be all of this at the same time!
        boolean grantTypeSet = false;
        if (grantTypes.contains("password")) {
            codegen.setOauth2Info(cs, flow);
            cs.isPassword = true;
            cs.flow = "password";
            grantTypeSet = true;
        }
        if (grantTypes.contains("implicit")) {
            codegen.setOauth2Info(cs, flow);
            cs.isImplicit = true;
            cs.flow = "implicit";
            grantTypeSet = true;
        }
        if (grantTypes.contains("client_credentials")) {
            codegen.setOauth2Info(cs, flow);
            cs.isApplication = true;
            cs.flow = "application";
            grantTypeSet = true;
        }
        if (grantTypes.contains("authorization_code")) {
            codegen.setOauth2Info(cs, flow);
            cs.isCode = true;
            cs.flow = "accessCode";
            grantTypeSet = true;
        }
        if (!grantTypeSet) {
            throw new RuntimeException("Could not identify any openIdConnect flow in " + cs.name);
        }
    }

}
