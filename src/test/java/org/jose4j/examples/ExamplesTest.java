/*
 * Copyright 2012-2013 Brian Campbell
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

import junit.framework.TestCase;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.Use;
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

public void testParseJwksAndVerifyJwsExample() throws JoseException
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

    // The JWS header contains a Key ID, which  is a hint indicating which key
    // was used to secure the JWS. In this case (as will hopefully often be the case) the JWS Key ID
    // corresponds directly to   the Key ID in the JWK Set.
    String keyId = jws.getKeyIdHeaderValue();


    // Find a JWK from the JWK Set that has the same Key ID, uses the same Key Type (EC)
    // and is designated to be used for signatures.
    JsonWebKey jwk = jsonWebKeySet.findJsonWebKey(keyId, jws.getKeyType(), Use.SIGNATURE, null);

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
}
