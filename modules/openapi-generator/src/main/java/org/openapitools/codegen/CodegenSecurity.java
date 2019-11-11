/*
 * Copyright 2018 OpenAPI-Generator Contributors (https://openapi-generator.tech)
 * Copyright 2018 SmartBear Software
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.openapitools.codegen;

import java.util.ArrayList;
import java.util.*;

public class CodegenSecurity {
    public String name;
    public String type;
    public String scheme;
    // if isOpenIdConnect is true => isOAuth is also true, as Oidc is a (more) standardized way of OAuth2
    public Boolean hasMore, isBasic, isOAuth, isOpenIdConnect, isApiKey;
    // is Basic is true for all http authentication type. Those are to differentiate basic and bearer authentication
    public Boolean isBasicBasic, isBasicBearer;
    public String bearerFormat;
    public Map<String, Object> vendorExtensions = new HashMap<String, Object>();
    // ApiKey specific
    public String keyParamName;
    public Boolean isKeyInQuery, isKeyInHeader, isKeyInCookie;
    // Oauth specific
    public String flow, authorizationUrl, tokenUrl;
    public List<Map<String, Object>> scopes;
    public Boolean isCode, isPassword, isApplication, isImplicit;

    public static CodegenSecurity copy(CodegenSecurity toCopy) {
        CodegenSecurity result = new CodegenSecurity();
        if (toCopy.vendorExtensions != null) {
            result.vendorExtensions = new HashMap<>(toCopy.vendorExtensions);
        }
        result.scopes = new ArrayList<>();
        if (toCopy.scopes != null) {
            for (Map<String, Object> m : toCopy.scopes) {
                result.scopes.add(new HashMap<>(m));
            }
        }

        result.authorizationUrl = toCopy.authorizationUrl;
        result.flow = toCopy.flow;
        result.tokenUrl = toCopy.tokenUrl;

        result.name = toCopy.name;
        result.isImplicit = toCopy.isImplicit;
        result.isCode = toCopy.isCode;
        result.isOAuth = toCopy.isOAuth;
        result.isBasic = toCopy.isBasic;
        result.isApiKey = toCopy.isApiKey;

        return result;
    }

    public CodegenSecurity() {
    }

    @Override
    public String toString() {
        return String.format(Locale.ROOT, "%s(%s)", name, type);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        CodegenSecurity that = (CodegenSecurity) o;

        return Objects.equals(name, that.name) &&
            Objects.equals(type, that.type) &&
            Objects.equals(hasMore, that.hasMore) &&
            Objects.equals(isBasic, that.isBasic) &&
            Objects.equals(isBasicBasic, that.isBasicBasic) &&
            Objects.equals(isBasicBearer, that.isBasicBearer) &&
            Objects.equals(bearerFormat, that.bearerFormat) &&
            Objects.equals(isOAuth, that.isOAuth) &&
            Objects.equals(isOpenIdConnect, that.isOpenIdConnect) &&
            Objects.equals(isApiKey, that.isApiKey) &&
            Objects.equals(vendorExtensions, that.vendorExtensions) &&
            Objects.equals(keyParamName, that.keyParamName) &&
            Objects.equals(isKeyInQuery, that.isKeyInQuery) &&
            Objects.equals(isKeyInHeader, that.isKeyInHeader) &&
            Objects.equals(flow, that.flow) &&
            Objects.equals(authorizationUrl, that.authorizationUrl) &&
            Objects.equals(tokenUrl, that.tokenUrl) &&
            Objects.equals(isCode, that.isCode) &&
            Objects.equals(isPassword, that.isPassword) &&
            Objects.equals(isApplication, that.isApplication) &&
            Objects.equals(isImplicit, that.isImplicit) &&
            Objects.equals(scopes, that.scopes);
    }

    @Override
    public int hashCode() {
        return Objects.hash(
            name,
            type,
            hasMore,
            isBasic,
            isBasicBasic,
            isBasicBearer,
            bearerFormat,
            isOAuth,
            isOpenIdConnect,
            isApiKey,
            vendorExtensions,
            keyParamName,
            isKeyInQuery,
            isKeyInHeader,
            flow,
            authorizationUrl,
            tokenUrl,
            isCode,
            isPassword,
            isApplication,
            isImplicit,
            scopes);
    }

    // Return a copy of the security object, filtering out any scopes from the passed-in list.
    public CodegenSecurity filterByScopeNames(List<String> filterScopes) {
        CodegenSecurity filteredSecurity = new CodegenSecurity();
        // Copy all fields except the scopes.
        filteredSecurity.name = name;
        filteredSecurity.type = type;
        filteredSecurity.hasMore = false;
        filteredSecurity.isBasic = isBasic;
        filteredSecurity.isBasicBasic = isBasicBasic;
        filteredSecurity.isBasicBearer = isBasicBearer;
        filteredSecurity.isApiKey = isApiKey;
        filteredSecurity.isOAuth = isOAuth;
        filteredSecurity.keyParamName = keyParamName;
        filteredSecurity.isCode = isCode;
        filteredSecurity.isImplicit = isImplicit;
        filteredSecurity.isApplication = isApplication;
        filteredSecurity.isPassword = isPassword;
        filteredSecurity.isKeyInCookie = isKeyInCookie;
        filteredSecurity.isKeyInHeader = isKeyInHeader;
        filteredSecurity.isKeyInQuery = isKeyInQuery;
        filteredSecurity.flow = flow;
        filteredSecurity.tokenUrl = tokenUrl;
        filteredSecurity.authorizationUrl = authorizationUrl;
        // It is not possible to deep copy the extensions, as we have no idea what types they are.
        // So the filtered method *will* refer to the original extensions, if any.
        filteredSecurity.vendorExtensions = new HashMap<String, Object>(vendorExtensions);
        List<Map<String, Object>> returnedScopes = new ArrayList<Map<String, Object>>();
        Map<String, Object> lastScope = null;
        for (String filterScopeName : filterScopes) {
            for (Map<String, Object> scope : scopes) {
                String name = (String) scope.get("scope");
                if (filterScopeName.equals(name)) {
                    returnedScopes.add(scope);
                    lastScope = scope;
                    break;
                }
            }
        }
        filteredSecurity.scopes = returnedScopes;

        return filteredSecurity;
    }
}
