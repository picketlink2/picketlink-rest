package org.picketlink.test.rest.api;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.HashMap;
import java.util.Map;

import org.junit.Ignore;
import org.junit.Test;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.rest.api.PicketLinkRestClient;

public class PicketLinkRestClientUnitTest {

    @Test @Ignore
    public void testSAML20IDP() throws Exception {
        PicketLinkRestClient client = new PicketLinkRestClient();
        Map<String,String> options = new HashMap<String, String>();
        
        options.put("idpURL", "http://localhost:8080/idp/");
        options.put("serviceURL", "http://localhost:8080/sp/");
        options.put("authType", "FORM");
        options.put("issuer", "http://localhost:8080/sp/");
        
        client.connect(options);
        AssertionType assertion = client.callSAML20IDP("tomcat", "tomcat");
        assertNotNull(assertion);
        assertEquals("tomcat",client.userName(assertion));
    }
    
    @Test @Ignore
    public void testSAML20IDPBasic() throws Exception {
        PicketLinkRestClient client = new PicketLinkRestClient();
        Map<String,String> options = new HashMap<String, String>();
        
        options.put("idpURL", "http://localhost:8080/idp-basic/");
        options.put("serviceURL", "http://localhost:8080/sp/");
        options.put("authType", "BASIC");
        options.put("issuer", "http://localhost:8080/sp/");
        options.put("realm", "PicketLink IDP Application");
        
        client.connect(options);
        AssertionType assertion = client.callSAML20IDP("tomcat", "tomcat");
        assertNotNull(assertion);
        assertEquals("tomcat",client.userName(assertion));
    }
}