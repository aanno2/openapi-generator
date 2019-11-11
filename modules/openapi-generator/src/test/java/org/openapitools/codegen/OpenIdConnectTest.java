package org.openapitools.codegen;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.Test;

import java.io.IOException;
import java.net.URL;

public class OpenIdConnectTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(OpenIdConnectTest.class);

    private static final String OPENID_CONFIGURATION = "./3_0/openidconnect/keycloak-openid-configuration.json";

    private DefaultCodegen codegen = new DefaultCodegen();

    @Test
    public void testOpenIdConfiguration() throws IOException {
        URL config = Thread.currentThread().getContextClassLoader().getResource(OPENID_CONFIGURATION);
        OpenIdConnect dut = new OpenIdConnect(codegen, config.toExternalForm()).retrieve();
        CodegenSecurity cs = new CodegenSecurity();
        dut.addToSecurity(cs);

        LOGGER.info(cs.toString());
    }
}
