package com.inomera.ssl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class CompositeX509TrustManager implements X509TrustManager {
    private static final Logger LOG = LoggerFactory.getLogger(CompositeX509TrustManager.class);

    private final X509TrustManager[] trustManagers;
    private final TrustManagerStrategy strategy;

    public CompositeX509TrustManager(TrustManagerStrategy strategy, X509TrustManager... trustManagers) {
        this.strategy = strategy == null ? defaultStrategy() : strategy;
        this.trustManagers = trustManagers;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) {
        if (!isClientCertificateTrustedByAnyManager(chain, authType)) {
            LOG.warn("Client certificate is not trusted by any TrustManager");
            strategy.onClientTrustFailure(chain, authType);
        }
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) {
        if (!isServerCertificateTrustedByAnyManager(chain, authType)) {
            LOG.warn("Server certificate is not trusted by any TrustManager");
            strategy.onServerTrustFailure(chain, authType);
        }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return Arrays.stream(trustManagers)
            .flatMap(trustManager -> Arrays.stream(trustManager.getAcceptedIssuers()))
            .toArray(X509Certificate[]::new);
    }

    private static TrustManagerStrategy defaultStrategy() {
        return new TrustManagerStrategy() {
            @Override
            public void onClientTrustFailure(X509Certificate[] chain, String authType) {
            }

            @Override
            public void onServerTrustFailure(X509Certificate[] chain, String authType) {
            }
        };
    }

    private boolean isServerCertificateTrustedByAnyManager(X509Certificate[] chain, String authType) {
        return Arrays.stream(trustManagers)
            .anyMatch(trustManager -> validateServerCertificate(trustManager, chain, authType));
    }

    private boolean isClientCertificateTrustedByAnyManager(X509Certificate[] chain, String authType) {
        return Arrays.stream(trustManagers)
            .anyMatch(trustManager -> validateClientCertificate(trustManager, chain, authType));
    }

    private boolean validateServerCertificate(X509TrustManager trustManager, X509Certificate[] chain, String authType) {
        try {
            trustManager.checkServerTrusted(chain, authType);
            return true;
        } catch (CertificateException e) {
            // Log and continue to the next TrustManager
            return false;
        }
    }

    private boolean validateClientCertificate(X509TrustManager trustManager, X509Certificate[] chain, String authType) {
        try {
            trustManager.checkClientTrusted(chain, authType);
            return true;
        } catch (CertificateException e) {
            // Log and continue to the next TrustManager
            return false;
        }
    }
}
