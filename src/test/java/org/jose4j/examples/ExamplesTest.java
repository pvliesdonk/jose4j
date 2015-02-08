/*
 * Copyright 2012-2015 Brian Campbell
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

package org.jose4j.examples;

import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.*;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.*;
import org.jose4j.keys.AesKey;
import org.jose4j.keys.ExampleEcKeysFromJws;
import org.jose4j.keys.X509Util;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;
import org.jose4j.keys.resolvers.JwksVerificationKeyResolver;
import org.jose4j.keys.resolvers.X509VerificationKeyResolver;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.JoseException;
import org.junit.Test;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

/**
 * There's probably a better way to do this but this is intended as a place to write and try and maintain
 * example code for the project wiki at https://bitbucket.org/b_c/jose4j/wiki/Home
 */
public class ExamplesTest
{

@Test
public void jwtRoundTripExample() throws JoseException
{
    //
    // JSON Web Token is a compact URL-safe means of representing claims/attributes to be transferred between two parties.
    // This example demonstrates producing and consuming a signed JWT
    //

    // Generate an RSA key pair, which will be used for signing and verification of the JWT, wrapped in a JWK
    RsaJsonWebKey rsaJsonWebKey = RsaJwkGenerator.generateJwk(2048);

    // Give the JWK a Key ID (kid), which is just the polite thing to do
    rsaJsonWebKey.setKeyId("k1");

    // Create the Claims, which will be the content of the JWT
    JwtClaims claims = new JwtClaims();
    claims.setIssuer("Issuer");  // who creates the token and signs it
    claims.setAudience("Audience"); // to whom the token is intended to be sent
    claims.setExpirationTimeMinutesInTheFuture(10); // time when the token will expire (10 minutes from now)
    claims.setGeneratedJwtId(); // a unique identifier for the token
    claims.setIssuedAtToNow();  // when the token was issued/created (now)
    claims.setNotBeforeMinutesInThePast(2); // time before which the token is not yet valid (2 minutes ago)
    claims.setSubject("subject"); // the subject/principal is whom the token is about
    claims.setClaim("email","mail@example.com"); // additional claims/attributes about the subject can be added
    List<String> groups = Arrays.asList("group-one", "other-group", "group-three");
    claims.setStringListClaim("groups", groups); // multi-valued claims work too and will end up as a JSON array

    // A JWT is a JWS and/or a JWE with JSON claims as the payload.
    // In this example it is a JWS so we create a JsonWebSignature object.
    JsonWebSignature jws = new JsonWebSignature();

    // The payload of the JWS is JSON content of the JWT Claims
    jws.setPayload(claims.toJson());

    // The JWT is signed using the private key
    jws.setKey(rsaJsonWebKey.getPrivateKey());

    // Set the Key ID (kid) header because it's just the polite thing to do.
    // We only have one key in this example but a using a Key ID helps
    // facilitate a smooth key rollover process
    jws.setKeyIdHeaderValue(rsaJsonWebKey.getKeyId());

    // Set the signature algorithm on the JWT/JWS that will integrity protect the claims
    jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);

    // Sign the JWS and produce the compact serialization or the complete JWT/JWS
    // representation, which is a string consisting of three dot ('.') separated
    // base64url-encoded parts in the form Header.Payload.Signature
    // If you wanted to encrypt it, you can simply set this jwt as the payload
    // of a JsonWebEncryption object and set the cty (Content Type) header to "jwt".
    String jwt = jws.getCompactSerialization();


    // Now you can something with the JWT. Like send it to some other party
    // over the clouds and through the interwebs.
    System.out.println("JWT: " + jwt);


    // Use JwtConsumerBuilder to construct an appropriate JwtConsumer, which will
    // be used to validate and process the JWT.
    // The specific validation requirements for a JWT are context dependent, however,
    // it typically advisable to require a expiration time, a trusted issuer, and
    // and audience that identifies your system as the intended recipient.
    // If the JWT is encrypted too, you need only provide a decryption key or
    // decryption key resolver to the builder.
    JwtConsumer jwtConsumer = new JwtConsumerBuilder()
            .setRequireExpirationTime() // the JWT must have an expiration time
            .setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account for clock skew
            .setRequireSubject() // the JWT must have a subject claim
            .setExpectedIssuer("Issuer") // whom the JWT needs to have been issued by
            .setExpectedAudience("Audience") // to whom the JWT is intended for
            .setVerificationKey(rsaJsonWebKey.getKey()) // verify the signature with the public key
            .build(); // create the JwtConsumer instance

    try
    {
        //  Validate the JWT and process it to the Claims
        JwtClaims jwtClaims = jwtConsumer.processToClaims(jwt);
        System.out.println("JWT validation succeeded! " + jwtClaims);
    }
    catch (InvalidJwtException e)
    {
        // InvalidJwtException will be thrown, if the JWT failed processing or validation in anyway.
        // Hopefully with meaningful explanations(s) about what went wrong.
        System.out.println("Invalid JWT! " + e);
    }


    // In the example above we generated a key pair and used it directly for signing and verification.
    // Key exchange in the real word, however, is rarely so simple.
    // A common pattern that's emerging is for an issuer to publish its public keys
    // as a JSON Web Key Set at an HTTPS endpoint. And for the consumer of the JWT to periodically,
    // based on cache directives or known/unknown Key IDs, retrieve the keys from the host authenticated
    // and secured endpoint.

    // The HttpsJwks retrieves and caches keys from a the given HTTPS JWKS endpoint.
    // Because it retains the JWKs after fetching them, it can and should be reused
    // to improve efficiency by reducing the number of outbound calls the the endpoint.
    HttpsJwks httpsJkws = new HttpsJwks("https://example.com/jwks");

    // The HttpsJwksVerificationKeyResolver uses JWKs obtained from the HttpsJwks and will select the
    // most appropriate one to use for verification based on the Key ID and other factors provided
    // in the header of the JWS/JWT.
    HttpsJwksVerificationKeyResolver httpsJwksKeyResolver = new HttpsJwksVerificationKeyResolver(httpsJkws);


    // Use JwtConsumerBuilder to construct an appropriate JwtConsumer, which will
    // be used to validate and process the JWT. But, in this case, provide it with
    // the HttpsJwksVerificationKeyResolver instance rather than setting the
    // verification key explicitly.
    jwtConsumer = new JwtConsumerBuilder()
            // ... other set up of the JwtConsumerBuilder ...
            .setVerificationKeyResolver(httpsJwksKeyResolver)
            // ...
            .build();


    // There's also a key resolver that selects from among a given list of JWKs using the Key ID
    // and other factors provided in the header of the JWS/JWT.
    JsonWebKeySet jsonWebKeySet = new JsonWebKeySet(rsaJsonWebKey);
    JwksVerificationKeyResolver jwksResolver = new JwksVerificationKeyResolver(jsonWebKeySet.getJsonWebKeys());
    jwtConsumer = new JwtConsumerBuilder()
            // ... other set up of the JwtConsumerBuilder ...
            .setVerificationKeyResolver(jwksResolver)
            // ...
            .build();


    // Sometimes X509 certificate(s) are provided out-of-band somehow by the signer/issuer
    // and the X509VerificationKeyResolver is helpful for that situation. It will use
    // the X.509 Certificate Thumbprint Headers (x5t or x5t#S256) from the JWS/JWT to
    // select from among the provided certificates to get the public key for verification.
    X509Util x509Util = new X509Util();
    X509Certificate certificate = x509Util.fromBase64Der(
            "MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJB" +
            "gNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYD" +
            "VQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1" +
            "wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBg" +
            "NVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDV" +
            "QQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1w" +
            "YmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnH" +
            "YMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66" +
            "s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6" +
            "SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpn" +
            "fajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPq" +
            "PvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVk" +
            "aZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BA" +
            "QUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL" +
            "+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1" +
            "zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL" +
            "2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo" +
            "4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTq" +
            "gawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA==");

    X509Certificate otherCertificate = x509Util.fromBase64Der(
            "MIICUDCCAbkCBETczdcwDQYJKoZIhvcNAQEFBQAwbzELMAkGA1UEBhMCVVMxCzAJ" +
            "BgNVBAgTAkNPMQ8wDQYDVQQHEwZEZW52ZXIxFTATBgNVBAoTDFBpbmdJZGVudGl0" +
            "eTEXMBUGA1UECxMOQnJpYW4gQ2FtcGJlbGwxEjAQBgNVBAMTCWxvY2FsaG9zdDAe" +
            "Fw0wNjA4MTExODM1MDNaFw0zMzEyMjcxODM1MDNaMG8xCzAJBgNVBAYTAlVTMQsw" +
            "CQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRUwEwYDVQQKEwxQaW5nSWRlbnRp" +
            "dHkxFzAVBgNVBAsTDkJyaWFuIENhbXBiZWxsMRIwEAYDVQQDEwlsb2NhbGhvc3Qw" +
            "gZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJLrpeiY/Ai2gGFxNY8Tm/QSO8qg" +
            "POGKDMAT08QMyHRlxW8fpezfBTAtKcEsztPzwYTLWmf6opfJT+5N6cJKacxWchn/" +
            "dRrzV2BoNuz1uo7wlpRqwcaOoi6yHuopNuNO1ms1vmlv3POq5qzMe6c1LRGADyZh" +
            "i0KejDX6+jVaDiUTAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAMojbPEYJiIWgQzZc" +
            "QJCQeodtKSJl5+lA8MWBBFFyZmvZ6jUYglIQdLlc8Pu6JF2j/hZEeTI87z/DOT6U" +
            "uqZA83gZcy6re4wMnZvY2kWX9CsVWDCaZhnyhjBNYfhcOf0ZychoKShaEpTQ5UAG" +
            "wvYYcbqIWC04GAZYVsZxlPl9hoA=");

    X509VerificationKeyResolver x509VerificationKeyResolver = new X509VerificationKeyResolver(certificate, otherCertificate);

    // Optionally the X509VerificationKeyResolver can attempt to verify the signature
    // with the key from each of the provided certificates, if no X.509 Certificate
    // Thumbprint Header is present in the JWT/JWS.
    x509VerificationKeyResolver.setTryAllOnNoThumbHeader(true);

    jwtConsumer = new JwtConsumerBuilder()
            // ... other set up of the JwtConsumerBuilder ...
            .setVerificationKeyResolver(x509VerificationKeyResolver)
            // ...
            .build();


    // Note that on the producing side, the X.509 Certificate Thumbprint Header
    // can be set like this on the JWS (which is the JWT)
    jws.setX509CertSha1ThumbprintHeaderValue(certificate);
}

@Test
public void jwsSigningExample() throws JoseException
{
    //
    // An example of signing using JSON Web Signature (JWS)
    //

    // The content that will be signed
    String examplePayload = "This is some text that is to be signed.";

    // Create a new JsonWebSignature
    JsonWebSignature jws = new JsonWebSignature();

    // Set the payload, or signed content, on the JWS object
    jws.setPayload(examplePayload);

    // Set the signature algorithm on the JWS that will integrity protect the payload
    jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);

    // Set the signing key on the JWS
    // Note that your application will need to determine where/how to get the key
    // and here we just use an example from the JWS spec
    PrivateKey privateKey = ExampleEcKeysFromJws.PRIVATE_256;
    jws.setKey(privateKey);

    // Sign the JWS and produce the compact serialization or complete JWS representation, which
    // is a string consisting of three dot ('.') separated base64url-encoded
    // parts in the form Header.Payload.Signature
    String jwsCompactSerialization = jws.getCompactSerialization();

    // Do something useful with your JWS
    System.out.println(jwsCompactSerialization);
}

@Test
public void jwsVerificationExample() throws JoseException
{
    //
    // An example of signature verification using JSON Web Signature (JWS)
    //

    // The complete JWS representation, or compact serialization, is string consisting of
    // three dot ('.') separated base64url-encoded parts in the form Header.Payload.Signature
    String compactSerialization = "eyJhbGciOiJFUzI1NiJ9." +
            "VGhpcyBpcyBzb21lIHRleHQgdGhhdCBpcyB0byBiZSBzaWduZWQu." +
            "GHiNd8EgKa-2A4yJLHyLCqlwoSxwqv2rzGrvUTxczTYDBeUHUwQRB3P0dp_DALL0jQIDz2vQAT_cnWTIW98W_A";

    // Create a new JsonWebSignature
    JsonWebSignature jws = new JsonWebSignature();

    // Set the compact serialization on the JWS
    jws.setCompactSerialization(compactSerialization);

    // Set the verification key
    // Note that your application will need to determine where/how to get the key
    // Here we use an example from the JWS spec
    PublicKey publicKey = ExampleEcKeysFromJws.PUBLIC_256;
    jws.setKey(publicKey);

    // Check the signature
    boolean signatureVerified = jws.verifySignature();

    // Do something useful with the result of signature verification
    System.out.println("JWS Signature is valid: " + signatureVerified);

    // Get the payload, or signed content, from the JWS
    String payload = jws.getPayload();

    // Do something useful with the content
    System.out.println("JWS payload: " + payload);
}

@Test
public void parseJwksAndVerifyJwsExample() throws JoseException
{
    //
    // An example of signature verification using JSON Web Signature (JWS)
    // where the verification key is obtained from a JSON Web Key Set document.
    //

    // A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data structure that represents a
    // cryptographic key (often but not always a public key). A JSON Web Key Set (JWK Set) document
    // is a JSON data structure for representing one or more JSON Web Keys (JWK). A JWK Set might,
    // for example, be obtained from an HTTPS endpoint controlled by the signer but this example
    // presumes the JWK Set JSONhas already been acquired by some secure/trusted means.
    String jsonWebKeySetJson = "{\"keys\":[" +
            "{\"kty\":\"EC\",\"use\":\"sig\"," +
             "\"kid\":\"the key\"," +
             "\"x\":\"amuk6RkDZi-48mKrzgBN_zUZ_9qupIwTZHJjM03qL-4\"," +
             "\"y\":\"ZOESj6_dpPiZZR-fJ-XVszQta28Cjgti7JudooQJ0co\",\"crv\":\"P-256\"}," +
            "{\"kty\":\"EC\",\"use\":\"sig\"," +
            " \"kid\":\"other key\"," +
             "\"x\":\"eCNZgiEHUpLaCNgYIcvWzfyBlzlaqEaWbt7RFJ4nIBA\"," +
             "\"y\":\"UujFME4pNk-nU4B9h4hsetIeSAzhy8DesBgWppiHKPM\",\"crv\":\"P-256\"}]}";

    // The complete JWS representation, or compact serialization, is string consisting of
    // three dot ('.') separated base64url-encoded parts in the form Header.Payload.Signature
    String compactSerialization = "eyJhbGciOiJFUzI1NiIsImtpZCI6InRoZSBrZXkifQ." +
            "UEFZTE9BRCE."+
            "Oq-H1lk5G0rl6oyNM3jR5S0-BZQgTlamIKMApq3RX8Hmh2d2XgB4scvsMzGvE-OlEmDY9Oy0YwNGArLpzXWyjw";

    // Create a new JsonWebSignature object
    JsonWebSignature jws = new JsonWebSignature();

    // Set the compact serialization on the JWS
    jws.setCompactSerialization(compactSerialization);

    // Create a new JsonWebKeySet object with the JWK Set JSON
    JsonWebKeySet jsonWebKeySet = new JsonWebKeySet(jsonWebKeySetJson);

    // The JWS header contains information indicating which key was used to secure the JWS.
    // In this case (as will hopefully often be the case) the JWS Key ID
    // corresponds directly to the Key ID in the JWK Set.
    // The VerificationJwkSelector looks at Key ID, Key Type, designated use (signatures vs. encryption),
    // and the designated algorithm in order to select the appropriate key for verification from
    // a set of JWKs.
    VerificationJwkSelector jwkSelector = new VerificationJwkSelector();
    JsonWebKey jwk = jwkSelector.select(jws, jsonWebKeySet.getJsonWebKeys());

    // The verification key on the JWS is the public key from the JWK we pulled from the JWK Set.
    jws.setKey(jwk.getKey());

    // Check the signature
    boolean signatureVerified = jws.verifySignature();

    // Do something useful with the result of signature verification
    System.out.println("JWS Signature is valid: " + signatureVerified);

    // Get the payload, or signed content, from the JWS
    String payload = jws.getPayload();

    // Do something useful with the content
    System.out.println("JWS payload: " + payload);
}

@Test
public void jweRoundTripExample() throws JoseException
{
    //
    // An example showing the use of JSON Web Encryption (JWE) to encrypt and then decrypt some content
    // using a symmetric key and direct encryption.
    //

    // The content to be encrypted
    String message = "Well, as of this moment, they're on DOUBLE SECRET PROBATION!";

    // The shared secret or shared symmetric key represented as a octet sequence JSON Web Key (JWK)
    String jwkJson = "{\"kty\":\"oct\",\"k\":\"Fdh9u8rINxfivbrianbbVT1u232VQBZYKx1HGAGPt2I\"}";
    JsonWebKey jwk = JsonWebKey.Factory.newJwk(jwkJson);

    // Create a new Json Web Encryption object
    JsonWebEncryption senderJwe = new JsonWebEncryption();

    // The plaintext of the JWE is the message that we want to encrypt.
    senderJwe.setPlaintext(message);

    // Set the "alg" header, which indicates the key management mode for this JWE.
    // In this example we are using the direct key management mode, which means
    // the given key will be used directly as the content encryption key.
    senderJwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.DIRECT);

    // Set the "enc" header, which indicates the content encryption algorithm to be used.
    // This example is using AES_128_CBC_HMAC_SHA_256 which is a composition of AES CBC
    // and HMAC SHA2 that provides authenticated encryption.
    senderJwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);

    // Set the key on the JWE. In this case, using direct mode, the key will used directly as
    // the content encryption key. AES_128_CBC_HMAC_SHA_256, which is being used to encrypt the
    // content requires a 256 bit key.
    senderJwe.setKey(jwk.getKey());

    // Produce the JWE compact serialization, which is where the actual encryption is done.
    // The JWE compact serialization consists of five base64url encoded parts
    // combined with a dot ('.') character in the general format of
    // <header>.<encrypted key>.<initialization vector>.<ciphertext>.<authentication tag>
    // Direct encryption doesn't use an encrypted key so that field will be an empty string
    // in this case.
    String compactSerialization = senderJwe.getCompactSerialization();

    // Do something with the JWE. Like send it to some other party over the clouds
    // and through the interwebs.
    System.out.println("JWE compact serialization: " + compactSerialization);

    // That other party, the receiver, can then use JsonWebEncryption to decrypt the message.
    JsonWebEncryption receiverJwe = new JsonWebEncryption();

    // Set the compact serialization on new Json Web Encryption object
    receiverJwe.setCompactSerialization(compactSerialization);

    // Symmetric encryption, like we are doing here, requires that both parties have the same key.
    // The key will have had to have been securely exchanged out-of-band somehow.
    receiverJwe.setKey(jwk.getKey());

    // Get the message that was encrypted in the JWE. This step performs the actual decryption steps.
    String plaintext = receiverJwe.getPlaintextString();

    // And do whatever you need to do with the clear text message.
    System.out.println("plaintext: " + plaintext);
}

@Test
public void helloWorld() throws JoseException
{
Key key = new AesKey(ByteUtil.randomBytes(16));
JsonWebEncryption jwe = new JsonWebEncryption();
jwe.setPayload("Hello World!");
jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.A128KW);
jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
jwe.setKey(key);
String serializedJwe = jwe.getCompactSerialization();
System.out.println("Serialized Encrypted JWE: " + serializedJwe);
jwe = new JsonWebEncryption();
jwe.setKey(key);
jwe.setCompactSerialization(serializedJwe);
System.out.println("Payload: " + jwe.getPayload());
}
}
