package org.jose4j.examples;

import junit.framework.TestCase;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.keys.ExampleEcKeysFromJws;
import org.jose4j.lang.JoseException;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * There's probably a better way to do this but this is intended as a place to write and try and maintain
 * example code for the project wiki at https://bitbucket.org/b_c/jose4j/wiki/Home
 */
public class ExamplesTest extends TestCase
{

public void testJwsSigningExample() throws JoseException
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

public void testJwsVerificationExample() throws JoseException
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
}
