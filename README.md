# SSL Forge


![Build](https://github.com/inomera/ssl-forge/workflows/Build/badge.svg)



| Artifact          | Version                                                                                                                                                                                  |
|-------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| ssl-forge | [![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.inomera.telco/ssl-forge/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.inomera.telco/ssl-forge) |

---

`ssl-forge` is a Java library designed to enhance SSL/TLS configurations by providing advanced mechanisms for managing
and validating X509 certificates. It allows you to define custom trust management strategies and supports multiple
`TrustManager` implementations through a composite pattern.

## Features

- **Composite Trust Management**: Combines multiple `TrustManager` implementations for server and client certificate
  validation.
- **Customizable Trust Strategies**: Define your own strategies for handling certificate validation failures.
- **Client and Server Support**: Independently manage client and server trust validation.
- **Streamlined API**: Easy-to-use builder for creating SSLContext instances.

---

## Installation

Add the following dependency to your `build.gradle` file:

```groovy
dependencies {
    implementation 'com.inomera.telco:ssl-forge:1.0.0'
}
```

For Maven, include the dependency:

```xml

<dependency>
    <groupId>com.inomera.telco</groupId>
    <artifactId>ssl-forge</artifactId>
    <version>1.0.0</version>
</dependency>
```

---

## Usage

### 1. Creating a CompositeX509TrustManager

The `CompositeX509TrustManager` allows you to combine multiple `TrustManager` implementations and apply custom
strategies for handling trust failures.

```java
X509TrustManager trustManager1 = ...; // Define your first TrustManager
X509TrustManager trustManager2 = ...; // Define your second TrustManager

TrustManagerStrategy strategy = new TrustManagerStrategy() {
    @Override
    public void onClientTrustFailure(X509Certificate[] chain, String authType) throws CertificateException {
        throw new CertificateException("Client certificate validation failed for authType: " + authType);
    }

    @Override
    public void onServerTrustFailure(X509Certificate[] chain, String authType) throws CertificateException {
        throw new CertificateException("Server certificate validation failed for authType: " + authType);
    }
};

CompositeX509TrustManager compositeTrustManager = new CompositeX509TrustManager(strategy, trustManager1, trustManager2);
```

### 2. Using the MultiTrustSSLContextBuilder

Easily build an `SSLContext` with the provided builder:

```java
MultiTrustSSLContextBuilder sslContextBuilder = MultiTrustSSLContextBuilder.create()
    .setTrustManagerStrategy(strategy)
    .loadTrustMaterial("path/to/truststore.jks", "truststorePassword".toCharArray());

SSLContext sslContext = sslContextBuilder.build();
```

### 3. Example: Secure Client Configuration

Use the `SSLContext` to configure a secure HTTP client:

```java
SSLContext sslContext = sslContextBuilder.build();

HttpClient client = HttpClient.newBuilder()
    .sslContext(sslContext)
    .build();
```

## Key Classes

### 1. `CompositeX509TrustManager`

A composite implementation of `X509TrustManager` that evaluates multiple trust managers.

- **Constructor**:
  ```java
  public CompositeX509TrustManager(TrustManagerStrategy strategy, X509TrustManager... trustManagers)
  ```

- **Methods**:
    - `checkClientTrusted`: Validates client certificates.
    - `checkServerTrusted`: Validates server certificates.

### 2. `TrustManagerStrategy`

An interface for defining custom trust failure handling strategies.

- **Methods**:
    - `onClientTrustFailure`: Called when client certificates fail validation.
    - `onServerTrustFailure`: Called when server certificates fail validation.

### 3. `MultiTrustSSLContextBuilder`

The `MultiTrustSSLContextBuilder` is an enhanced version of the widely used org.apache.http.ssl.SSLContextBuilder class.
While the original SSLContextBuilder provides a convenient way to configure and build an _SSLContext_ instance, it has
some limitations.

MultiTrustSSLContextBuilder class is a builder for creating `SSLContext` instances with custom trust managers.

## Gradle Java 17

If your JAVA_HOME is not Java17, create a `gradle.properties` file in project home and add this line:

```properties
    org.gradle.java.home=/Library/Java/JavaVirtualMachines/jdk-17.0.5.jdk/Contents/Home
```
