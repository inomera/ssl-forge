package com.inomera.ssl;

import java.security.cert.X509Certificate;

public interface TrustManagerStrategy {

    /**
     * Called when the client certificate chain is not trusted.
     *
     * @param chain    the certificate chain presented by the client
     * @param authType the authentication type used (e.g., RSA)
     */
    void onClientTrustFailure(X509Certificate[] chain, String authType);

    /**
     * Called when the server certificate chain is not trusted.
     *
     * @param chain    the certificate chain presented by the server
     * @param authType the authentication type used (e.g., RSA)
     */
    void onServerTrustFailure(X509Certificate[] chain, String authType);
}
