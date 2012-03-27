package org.picketlink.rest.api;

import java.security.GeneralSecurityException;

public class PicketLinkRestClientException extends GeneralSecurityException {

    private static final long serialVersionUID = 1L;

    public PicketLinkRestClientException() {
        super();
    }

    public PicketLinkRestClientException(String message, Throwable cause) {
        super(message, cause);
    }

    public PicketLinkRestClientException(String msg) {
        super(msg);
    }

    public PicketLinkRestClientException(Throwable cause) {
        super(cause);
    }
}