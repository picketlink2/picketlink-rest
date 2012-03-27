package org.picketlink.rest.api;

import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

import org.picketlink.identity.federation.api.saml.v2.request.SAML2Request;
import org.picketlink.identity.federation.core.exceptions.ConfigurationException;
import org.picketlink.identity.federation.core.parsers.saml.SAMLParser;
import org.picketlink.identity.federation.core.saml.v2.common.IDGenerator;
import org.picketlink.identity.federation.core.saml.v2.exceptions.AssertionExpiredException;
import org.picketlink.identity.federation.core.saml.v2.util.AssertionUtil;
import org.picketlink.identity.federation.core.saml.v2.util.DocumentUtil;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectType.STSubType;
import org.picketlink.identity.federation.saml.v2.protocol.AuthnRequestType;
import org.picketlink.identity.federation.saml.v2.protocol.ResponseType;
import org.picketlink.identity.federation.web.util.PostBindingUtil;
import org.w3c.dom.Document;

import com.meterware.httpunit.FormControl;
import com.meterware.httpunit.FormParameter;
import com.meterware.httpunit.HttpUnitOptions;
import com.meterware.httpunit.PostMethodWebRequest;
import com.meterware.httpunit.SubmitButton;
import com.meterware.httpunit.WebConversation;
import com.meterware.httpunit.WebForm;
import com.meterware.httpunit.WebResponse;

/**
 * A Client that uses rest concepts to make SSO calls
 *
 * @author anil saldhana
 */
public class PicketLinkRestClient {
    private WebConversation webConversation;

    public enum AUTH_TYPE {
        BASIC, FORM, CLIENT_CERT
    };

    private Map<String, String> options = new HashMap<String, String>();

    /**
     * Connect to a security system
     *
     * @param theoptions a set of configuration options
     */
    public void connect(Map<String, String> theoptions) {
        if (webConversation == null) {
            webConversation = new WebConversation();
            HttpUnitOptions.setScriptingEnabled(false);
        }
        options.putAll(theoptions);
    }

    /**
     * Disconnect from the security system
     */
    public void disconnect() {
        webConversation = null;
    }

    /**
     * Call a SAML20 IDP using HTTP/POST Binding
     *
     * @param username
     * @param credential
     * @return
     * @throws PicketLinkRestClientException
     */
    public AssertionType callSAML20IDP(String username, Object credential) throws PicketLinkRestClientException {
        AUTH_TYPE authType = AUTH_TYPE.valueOf(options.get("authType"));
        String idpURL = options.get("idpURL");
        String serviceURL = options.get("serviceURL");

        String issuer = options.get("issuer");


        if (authType == AUTH_TYPE.FORM) {
            try {
                WebResponse webResponse = prepareInitialPostRequestSAML20IDP(idpURL,serviceURL,issuer);

                WebForm loginForm = webResponse.getForms()[0];
                loginForm.setParameter("j_username", username);
                loginForm.setParameter("j_password", (String) credential);
                SubmitButton submitButton = loginForm.getSubmitButtons()[0];
                submitButton.click();

                return getAssertion();
            } catch (Exception e) {
                throw new PicketLinkRestClientException(e);
            }
        } else if (authType == AUTH_TYPE.BASIC){
            try { 
                webConversation.setAuthentication(options.get("realm"), username, (String) credential);
                prepareInitialPostRequestSAML20IDP(idpURL,serviceURL,issuer);

                return getAssertion();
            } catch (Exception e) {
                throw new PicketLinkRestClientException(e);
            }
        }
        return null;
    }

    public String userName(AssertionType assertion) throws PicketLinkRestClientException {
        // Check for validity of assertion
        boolean expiredAssertion = true;
        try {
            expiredAssertion = AssertionUtil.hasExpired(assertion);
        } catch (ConfigurationException e) {
            throw new PicketLinkRestClientException(e);
        }
        if (expiredAssertion) {
            AssertionExpiredException ae = new AssertionExpiredException();
            throw new PicketLinkRestClientException(ae);
        }

        SubjectType subject = assertion.getSubject();

        if (subject == null)
            throw new PicketLinkRestClientException(" Null Subject in the assertion");

        STSubType subType = subject.getSubType();
        if (subType == null)
            throw new PicketLinkRestClientException("Unable to find subtype via subject");
        NameIDType nameID = (NameIDType) subType.getBaseID();

        if (nameID == null)
            throw new PicketLinkRestClientException("Unable to find username via subject");

        return nameID.getValue();
    }
    
    private WebResponse prepareInitialPostRequestSAML20IDP(String idpURL, String serviceURL, String issuer) throws Exception{
        String id = IDGenerator.create("ID_");
        PostMethodWebRequest idpRequest = new PostMethodWebRequest(idpURL);

        // Construct a AuthnRequestType
        SAML2Request samlRequest = new SAML2Request();
        AuthnRequestType authn = samlRequest.createAuthnRequestType(id, serviceURL, serviceURL, issuer);

        Document authnDoc = samlRequest.convert(authn);

        String samlMessage = DocumentUtil.getDocumentAsString(authnDoc);
        samlMessage = PostBindingUtil.base64Encode(samlMessage);
        idpRequest.setParameter("SAMLRequest", samlMessage);

        return webConversation.sendRequest(idpRequest);
    }
    
    private AssertionType getAssertion() throws Exception {
        WebResponse webResponse = webConversation.getCurrentPage();
        WebForm responseForm = webResponse.getForms()[0];
        FormParameter formParameter = responseForm.getParameter("SAMLResponse");
        FormControl formControl = formParameter.getControl();
        String samlResponse = formControl.getAttribute("value");

        InputStream is = PostBindingUtil.base64DecodeAsStream(samlResponse);
        SAMLParser parser = new SAMLParser();
        ResponseType response = (ResponseType) parser.parse(is);
        return response.getAssertions().get(0).getAssertion();
    }
}