package com.inomera.ssl;

import org.apache.http.ssl.PrivateKeyDetails;
import org.apache.http.ssl.PrivateKeyStrategy;
import org.apache.http.ssl.TrustStrategy;
import org.apache.http.util.Args;

import javax.net.ssl.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.net.URL;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Builder for {@link javax.net.ssl.SSLContext} instances.
 * <p>
 * Please note: the default Oracle JSSE implementation of {@link SSLContext#init(KeyManager[], TrustManager[], SecureRandom)}
 * accepts multiple key and trust managers. Considers only the first matching {@code KeyManager} or {@code TrustManager}.
 * However, this builder introduces a composite mechanism that can combine multiple {@code TrustManager} instances, ensuring
 * that all configured trust managers are evaluated rather than only the first match.
 * <a href="http://docs.oracle.com/javase/7/docs/api/javax/net/ssl/SSLContext.html#init%28javax.net.ssl.KeyManager[],%20javax.net.ssl.TrustManager[],%20java.security.SecureRandom%29">
 * SSLContext.html#init
 * </a>
 *
 * @since 4.4
 */
public class MultiTrustSSLContextBuilder {

    static final String TLS = "TLS";

    private String protocol;
    private final Set<KeyManager> keyManagers;
    private String keyManagerFactoryAlgorithm = KeyManagerFactory.getDefaultAlgorithm();
    private String keyStoreType = KeyStore.getDefaultType();
    private final Set<TrustManager> trustManagers;
    private String trustManagerFactoryAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
    private SecureRandom secureRandom;
    private Provider provider;
    private TrustManagerStrategy trustManagerStrategy;

    public static MultiTrustSSLContextBuilder create() {
        return new MultiTrustSSLContextBuilder();
    }

    public MultiTrustSSLContextBuilder() {
        super();
        this.keyManagers = new LinkedHashSet<KeyManager>();
        this.trustManagers = new LinkedHashSet<TrustManager>();
    }

    /**
     * Sets the SSLContext protocol algorithm name.
     *
     * @param protocol the SSLContext protocol algorithm name of the requested protocol. See
     *                 the SSLContext section in the <a href=
     *                 "https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#SSLContext">Java
     *                 Cryptography Architecture Standard Algorithm Name
     *                 Documentation</a> for more information.
     * @return this builder
     * @see <a href=
     * "https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#SSLContext">Java
     * Cryptography Architecture Standard Algorithm Name Documentation</a>
     * @deprecated Use {@link #setProtocol(String)}.
     */
    @Deprecated
    public MultiTrustSSLContextBuilder useProtocol(final String protocol) {
        this.protocol = protocol;
        return this;
    }

    /**
     * Sets the SSLContext protocol algorithm name.
     *
     * @param protocol the SSLContext protocol algorithm name of the requested protocol. See
     *                 the SSLContext section in the <a href=
     *                 "https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#SSLContext">Java
     *                 Cryptography Architecture Standard Algorithm Name
     *                 Documentation</a> for more information.
     * @return this builder
     * @see <a href=
     * "https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#SSLContext">Java
     * Cryptography Architecture Standard Algorithm Name Documentation</a>
     * @since 4.4.7
     */
    public MultiTrustSSLContextBuilder setProtocol(final String protocol) {
        this.protocol = protocol;
        return this;
    }

    public MultiTrustSSLContextBuilder setSecureRandom(final SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
        return this;
    }

    public MultiTrustSSLContextBuilder setProvider(final Provider provider) {
        this.provider = provider;
        return this;
    }

    public MultiTrustSSLContextBuilder setProvider(final String name) {
        this.provider = Security.getProvider(name);
        return this;
    }

    /**
     * Sets the key store type.
     *
     * @param keyStoreType the SSLkey store type. See
     *                     the KeyStore section in the <a href=
     *                     "https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyStore">Java
     *                     Cryptography Architecture Standard Algorithm Name
     *                     Documentation</a> for more information.
     * @return this builder
     * @see <a href=
     * "https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyStore">Java
     * Cryptography Architecture Standard Algorithm Name Documentation</a>
     * @since 4.4.7
     */
    public MultiTrustSSLContextBuilder setKeyStoreType(final String keyStoreType) {
        this.keyStoreType = keyStoreType;
        return this;
    }

    /**
     * Sets the key manager factory algorithm name.
     *
     * @param keyManagerFactoryAlgorithm the key manager factory algorithm name of the requested protocol. See
     *                                   the KeyManagerFactory section in the <a href=
     *                                   "https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyManagerFactory">Java
     *                                   Cryptography Architecture Standard Algorithm Name
     *                                   Documentation</a> for more information.
     * @return this builder
     * @see <a href=
     * "https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyManagerFactory">Java
     * Cryptography Architecture Standard Algorithm Name Documentation</a>
     * @since 4.4.7
     */
    public MultiTrustSSLContextBuilder setKeyManagerFactoryAlgorithm(final String keyManagerFactoryAlgorithm) {
        this.keyManagerFactoryAlgorithm = keyManagerFactoryAlgorithm;
        return this;
    }

    /**
     * Sets the trust manager factory algorithm name.
     *
     * @param trustManagerFactoryAlgorithm the trust manager algorithm name of the requested protocol. See
     *                                     the TrustManagerFactory section in the <a href=
     *                                     "https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#TrustManagerFactory">Java
     *                                     Cryptography Architecture Standard Algorithm Name
     *                                     Documentation</a> for more information.
     * @return this builder
     * @see <a href=
     * "https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#TrustManagerFactory">Java
     * Cryptography Architecture Standard Algorithm Name Documentation</a>
     * @since 4.4.7
     */
    public MultiTrustSSLContextBuilder setTrustManagerFactoryAlgorithm(final String trustManagerFactoryAlgorithm) {
        this.trustManagerFactoryAlgorithm = trustManagerFactoryAlgorithm;
        return this;
    }

    public MultiTrustSSLContextBuilder setTrustManagerStrategy(final TrustManagerStrategy trustManagerStrategy) {
        this.trustManagerStrategy = trustManagerStrategy;
        return this;
    }

    public MultiTrustSSLContextBuilder loadTrustMaterial(
        final KeyStore truststore,
        final TrustStrategy trustStrategy) throws NoSuchAlgorithmException, KeyStoreException {
        final TrustManagerFactory tmfactory = TrustManagerFactory
            .getInstance(trustManagerFactoryAlgorithm == null ? TrustManagerFactory.getDefaultAlgorithm()
                : trustManagerFactoryAlgorithm);
        tmfactory.init(truststore);
        final TrustManager[] tms = tmfactory.getTrustManagers();
        if (tms != null) {
            if (trustStrategy != null) {
                for (int i = 0; i < tms.length; i++) {
                    final TrustManager tm = tms[i];
                    if (tm instanceof X509TrustManager) {
                        tms[i] = new MultiTrustSSLContextBuilder.TrustManagerDelegate((X509TrustManager) tm, trustStrategy);
                    }
                }
            }
            Collections.addAll(this.trustManagers, tms);
        }
        return this;
    }

    public MultiTrustSSLContextBuilder loadTrustMaterial(
        final TrustStrategy trustStrategy) throws NoSuchAlgorithmException, KeyStoreException {
        return loadTrustMaterial(null, trustStrategy);
    }

    public MultiTrustSSLContextBuilder loadTrustMaterial(
        final File file,
        final char[] storePassword,
        final TrustStrategy trustStrategy) throws NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
        Args.notNull(file, "Truststore file");
        final KeyStore trustStore = KeyStore.getInstance(keyStoreType);
        final FileInputStream inStream = new FileInputStream(file);
        try {
            trustStore.load(inStream, storePassword);
        } finally {
            inStream.close();
        }
        return loadTrustMaterial(trustStore, trustStrategy);
    }

    public MultiTrustSSLContextBuilder loadTrustMaterial(
        final File file,
        final char[] storePassword) throws NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
        return loadTrustMaterial(file, storePassword, null);
    }

    public MultiTrustSSLContextBuilder loadTrustMaterial(
        final File file) throws NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
        return loadTrustMaterial(file, null);
    }

    public MultiTrustSSLContextBuilder loadTrustMaterial(
        final URL url,
        final char[] storePassword,
        final TrustStrategy trustStrategy) throws NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
        Args.notNull(url, "Truststore URL");
        final KeyStore trustStore = KeyStore.getInstance(keyStoreType);
        final InputStream inStream = url.openStream();
        try {
            trustStore.load(inStream, storePassword);
        } finally {
            inStream.close();
        }
        return loadTrustMaterial(trustStore, trustStrategy);
    }

    public MultiTrustSSLContextBuilder loadTrustMaterial(
        final URL url,
        final char[] storePassword) throws NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
        return loadTrustMaterial(url, storePassword, null);
    }

    public MultiTrustSSLContextBuilder loadKeyMaterial(
        final KeyStore keystore,
        final char[] keyPassword,
        final PrivateKeyStrategy aliasStrategy)
        throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
        final KeyManagerFactory kmfactory = KeyManagerFactory
            .getInstance(keyManagerFactoryAlgorithm == null ? KeyManagerFactory.getDefaultAlgorithm()
                : keyManagerFactoryAlgorithm);
        kmfactory.init(keystore, keyPassword);
        final KeyManager[] kms = kmfactory.getKeyManagers();
        if (kms != null) {
            if (aliasStrategy != null) {
                for (int i = 0; i < kms.length; i++) {
                    final KeyManager km = kms[i];
                    if (km instanceof X509ExtendedKeyManager) {
                        kms[i] = new MultiTrustSSLContextBuilder.KeyManagerDelegate((X509ExtendedKeyManager) km, aliasStrategy);
                    }
                }
            }
            Collections.addAll(keyManagers, kms);
        }
        return this;
    }

    public MultiTrustSSLContextBuilder loadKeyMaterial(
        final KeyStore keystore,
        final char[] keyPassword) throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
        return loadKeyMaterial(keystore, keyPassword, null);
    }

    public MultiTrustSSLContextBuilder loadKeyMaterial(
        final File file,
        final char[] storePassword,
        final char[] keyPassword,
        final PrivateKeyStrategy aliasStrategy) throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException, CertificateException, IOException {
        Args.notNull(file, "Keystore file");
        final KeyStore identityStore = KeyStore.getInstance(keyStoreType);
        final FileInputStream inStream = new FileInputStream(file);
        try {
            identityStore.load(inStream, storePassword);
        } finally {
            inStream.close();
        }
        return loadKeyMaterial(identityStore, keyPassword, aliasStrategy);
    }

    public MultiTrustSSLContextBuilder loadKeyMaterial(
        final File file,
        final char[] storePassword,
        final char[] keyPassword) throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException, CertificateException, IOException {
        return loadKeyMaterial(file, storePassword, keyPassword, null);
    }

    public MultiTrustSSLContextBuilder loadKeyMaterial(
        final URL url,
        final char[] storePassword,
        final char[] keyPassword,
        final PrivateKeyStrategy aliasStrategy) throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException, CertificateException, IOException {
        Args.notNull(url, "Keystore URL");
        final KeyStore identityStore = KeyStore.getInstance(keyStoreType);
        final InputStream inStream = url.openStream();
        try {
            identityStore.load(inStream, storePassword);
        } finally {
            inStream.close();
        }
        return loadKeyMaterial(identityStore, keyPassword, aliasStrategy);
    }

    public MultiTrustSSLContextBuilder loadKeyMaterial(
        final URL url,
        final char[] storePassword,
        final char[] keyPassword) throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException, CertificateException, IOException {
        return loadKeyMaterial(url, storePassword, keyPassword, null);
    }

    protected void initSSLContext(
        final SSLContext sslContext,
        final Collection<KeyManager> keyManagers,
        final Collection<TrustManager> trustManagers,
        final SecureRandom secureRandom) throws KeyManagementException {
        sslContext.init(
            !keyManagers.isEmpty() ? keyManagers.toArray(new KeyManager[keyManagers.size()]) : null,
            !trustManagers.isEmpty() ? trustManagers.toArray(new TrustManager[trustManagers.size()]) : null,
            secureRandom);
    }

    public SSLContext build() throws NoSuchAlgorithmException, KeyManagementException {
        final SSLContext sslContext;
        final String protocolStr = this.protocol != null ? this.protocol : TLS;
        if (this.provider != null) {
            sslContext = SSLContext.getInstance(protocolStr, this.provider);
        } else {
            sslContext = SSLContext.getInstance(protocolStr);
        }
        initSSLContext(sslContext, keyManagers, toCompositeTrustManager(), secureRandom);
        return sslContext;
    }

    static class TrustManagerDelegate implements X509TrustManager {

        private final X509TrustManager trustManager;
        private final TrustStrategy trustStrategy;

        TrustManagerDelegate(final X509TrustManager trustManager, final TrustStrategy trustStrategy) {
            super();
            this.trustManager = trustManager;
            this.trustStrategy = trustStrategy;
        }

        @Override
        public void checkClientTrusted(
            final X509Certificate[] chain, final String authType) throws CertificateException {
            this.trustManager.checkClientTrusted(chain, authType);
        }

        @Override
        public void checkServerTrusted(
            final X509Certificate[] chain, final String authType) throws CertificateException {
            if (!this.trustStrategy.isTrusted(chain, authType)) {
                this.trustManager.checkServerTrusted(chain, authType);
            }
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return this.trustManager.getAcceptedIssuers();
        }

    }

    static class KeyManagerDelegate extends X509ExtendedKeyManager {

        private final X509ExtendedKeyManager keyManager;
        private final PrivateKeyStrategy aliasStrategy;

        KeyManagerDelegate(final X509ExtendedKeyManager keyManager, final PrivateKeyStrategy aliasStrategy) {
            super();
            this.keyManager = keyManager;
            this.aliasStrategy = aliasStrategy;
        }

        @Override
        public String[] getClientAliases(
            final String keyType, final Principal[] issuers) {
            return this.keyManager.getClientAliases(keyType, issuers);
        }

        public Map<String, PrivateKeyDetails> getClientAliasMap(
            final String[] keyTypes, final Principal[] issuers) {
            final Map<String, PrivateKeyDetails> validAliases = new HashMap<String, PrivateKeyDetails>();
            for (final String keyType : keyTypes) {
                final String[] aliases = this.keyManager.getClientAliases(keyType, issuers);
                if (aliases != null) {
                    for (final String alias : aliases) {
                        validAliases.put(alias,
                            new PrivateKeyDetails(keyType, this.keyManager.getCertificateChain(alias)));
                    }
                }
            }
            return validAliases;
        }

        public Map<String, PrivateKeyDetails> getServerAliasMap(
            final String keyType, final Principal[] issuers) {
            final Map<String, PrivateKeyDetails> validAliases = new HashMap<String, PrivateKeyDetails>();
            final String[] aliases = this.keyManager.getServerAliases(keyType, issuers);
            if (aliases != null) {
                for (final String alias : aliases) {
                    validAliases.put(alias,
                        new PrivateKeyDetails(keyType, this.keyManager.getCertificateChain(alias)));
                }
            }
            return validAliases;
        }

        @Override
        public String chooseClientAlias(
            final String[] keyTypes, final Principal[] issuers, final Socket socket) {
            final Map<String, PrivateKeyDetails> validAliases = getClientAliasMap(keyTypes, issuers);
            return this.aliasStrategy.chooseAlias(validAliases, socket);
        }

        @Override
        public String[] getServerAliases(
            final String keyType, final Principal[] issuers) {
            return this.keyManager.getServerAliases(keyType, issuers);
        }

        @Override
        public String chooseServerAlias(
            final String keyType, final Principal[] issuers, final Socket socket) {
            final Map<String, PrivateKeyDetails> validAliases = getServerAliasMap(keyType, issuers);
            return this.aliasStrategy.chooseAlias(validAliases, socket);
        }

        @Override
        public X509Certificate[] getCertificateChain(final String alias) {
            return this.keyManager.getCertificateChain(alias);
        }

        @Override
        public PrivateKey getPrivateKey(final String alias) {
            return this.keyManager.getPrivateKey(alias);
        }

        @Override
        public String chooseEngineClientAlias(
            final String[] keyTypes, final Principal[] issuers, final SSLEngine sslEngine) {
            final Map<String, PrivateKeyDetails> validAliases = getClientAliasMap(keyTypes, issuers);
            return this.aliasStrategy.chooseAlias(validAliases, null);
        }

        @Override
        public String chooseEngineServerAlias(
            final String keyType, final Principal[] issuers, final SSLEngine sslEngine) {
            final Map<String, PrivateKeyDetails> validAliases = getServerAliasMap(keyType, issuers);
            return this.aliasStrategy.chooseAlias(validAliases, null);
        }

    }

    @Override
    public String toString() {
        return "[provider=" + provider + ", protocol=" + protocol + ", keyStoreType=" + keyStoreType
               + ", keyManagerFactoryAlgorithm=" + keyManagerFactoryAlgorithm + ", keyManagers=" + keyManagers
               + ", trustManagerFactoryAlgorithm=" + trustManagerFactoryAlgorithm + ", trustManagers=" + trustManagers
               + ", secureRandom=" + secureRandom + "]";
    }

    private Collection<TrustManager> toCompositeTrustManager() {
        X509TrustManager[] array = this.trustManagers.stream()
            .map(trustManager -> (X509TrustManager) trustManager)
            .toArray(X509TrustManager[]::new);
        return List.of(new CompositeX509TrustManager(trustManagerStrategy, array));
    }
}
