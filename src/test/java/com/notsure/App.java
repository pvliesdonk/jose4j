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

package com.notsure;

import org.jose4j.base64url.Base64Url;
import org.jose4j.jwk.*;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwx.CompactSerializer;
import org.jose4j.keys.*;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.JoseException;
import org.jose4j.json.JsonUtil;
import org.jose4j.lang.StringUtil;
import org.jose4j.mac.MacUtil;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Arrays;
import java.util.Map;


/**
 * Hello world!
 */
public class App 
{
    private static final String DOT = ".";

    static String newline = new String(new char[]{0x0d, 0x0a});

    public static void main(String[] args) throws Exception
    {
        // http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-11#appendix-A.2
        String plainText = "Live long and prosper.";
        byte[] plainTextBytes = StringUtil.getBytesUtf8(plainText);
        int[] plainTextUnsignedBytesFromExample = new int[] {76, 105, 118, 101, 32, 108, 111, 110, 103, 32, 97, 110, 100, 32,
           112, 114, 111, 115, 112, 101, 114, 46};
        System.out.println("plaintext bytes equal " + Arrays.equals(plainTextBytes, ByteUtil.convertUnsignedToSignedTwosComp(plainTextUnsignedBytesFromExample)));

        String jweHeaderString = "{\"alg\":\"RSA1_5\",\"enc\":\"A128CBC-HS256\"}";

        Base64Url b64 = new Base64Url();
        String encodedHeader = b64.base64UrlEncodeUtf8ByteRepresentation(jweHeaderString);
        System.out.println("encodedHeader.equals"+encodedHeader.equals("eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0"));

        Cipher rsa15cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsa15cipher.init(Cipher.WRAP_MODE, ExampleRsaJwksFromJwe.APPENDIX_A_2.getPublicKey());  // wrap or encrypt? does it matter?

        byte[] contentEncryptionKeyBytes = ByteUtil.convertUnsignedToSignedTwosComp(new int[]{4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207});
        System.out.println("contentEncryptionKeyBytes bytes " + Arrays.toString(contentEncryptionKeyBytes));
        System.out.println("contentEncryptionKeyBytes length " +contentEncryptionKeyBytes.length);
        SecretKeySpec contentEncryptionKey = new SecretKeySpec(contentEncryptionKeyBytes, "AES");
        byte[] encryptedCekBytes = rsa15cipher.wrap(contentEncryptionKey);
        System.out.println("encrypted key bytes " + Arrays.toString(encryptedCekBytes));
        System.out.println("encrypted key bytes length " +encryptedCekBytes.length);

        String encodedJweEncryptedKey = b64.base64UrlEncode(encryptedCekBytes);
        System.out.println("encodedJweEncryptedKey: " +encodedJweEncryptedKey);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        byte[] fullCekBytes = contentEncryptionKey.getEncoded();

        byte[] hmacKeyBytes = ByteUtil.leftHalf(fullCekBytes);
        byte[] encKeyBytes = ByteUtil.rightHalf(fullCekBytes);
        System.out.println(Arrays.toString(hmacKeyBytes));
        System.out.println(Arrays.toString(encKeyBytes));

        System.out.println(Arrays.toString(contentEncryptionKeyBytes));
        System.out.println(Arrays.toString(ByteUtil.concat(hmacKeyBytes, encKeyBytes)));

        byte[] iv = ByteUtil.convertUnsignedToSignedTwosComp(new int[]{3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101});
        System.out.println("iv " + iv.length);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encKeyBytes, "AES"), new IvParameterSpec(iv));
        byte[] iv2 = cipher.getIV();
        System.out.println("ivs eq " +Arrays.equals(iv, iv2));
        System.out.println("iv2 " + iv2.length);
        String encodedJweInitializationVector = b64.base64UrlEncode(iv);
        byte[] cipherText = cipher.doFinal(StringUtil.getBytesUtf8(plainText));


        byte[] aad = StringUtil.getBytesAscii(encodedHeader);
        System.out.println(Arrays.toString(aad));

        Mac mac = MacUtil.getInitializedMac(MacUtil.HMAC_SHA256, new HmacKey(hmacKeyBytes));

//        4.  The octet string AL is equal to the number of bits in A expressed
//            as a 64-bit unsigned integer in network byte order.

        long alvalue = ByteUtil.bitLength(aad);
        byte[] al = ByteUtil.getBytes(alvalue);





//        5.  A message authentication tag T is computed by applying HMAC
//            [RFC2104] to the following data, in order:
//
//               the associated data A,
//
//               the initialization vector IV,
//
//               the ciphertext E computed in the previous step, and
//
//               the octet string AL defined above.


        byte[] authenticationTagInput = ByteUtil.concat(aad, iv, cipherText, al);
        byte[] authenticationTag = mac.doFinal(authenticationTagInput);
        byte[] truncatedAuthenticationTag = ByteUtil.leftHalf(authenticationTag);

        String encodedAuthenticationTag = b64.base64UrlEncode(truncatedAuthenticationTag);
        String encodedCipherText = b64.base64UrlEncode(cipherText);

        System.out.println("encodedCipherText.equals " + encodedCipherText.equals("KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY"));
        System.out.println("encodedAuthenticationTag.equals " + encodedAuthenticationTag.equals("9hH0vgRfYgPnAHOd8stkvw"));


        String cs = CompactSerializer.serialize(encodedHeader, encodedJweEncryptedKey, encodedJweInitializationVector, encodedCipherText, encodedAuthenticationTag);

        decJweAppA2(cs);


        String csFromAppendixA2 = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." +
                "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm" +
                "1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7Pc" +
                "HALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIF" +
                "NPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8" +
                "rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv" +
                "-B3oWh2TbqmScqXMR4gp_A." +
                "AxY8DCtDaGlsbGljb3RoZQ." +
                "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY." +
                "9hH0vgRfYgPnAHOd8stkvw";

        decJweAppA2(csFromAppendixA2);

    }

    public static void decJweAppA2(String cs) throws JoseException, Exception
    {
        System.out.println("++++ decrypt +++++");
        System.out.println(cs);

        String[] deserialized = CompactSerializer.deserialize(cs);
        String encodedHeader = deserialized[0];
        String encodedJweEncryptedKey = deserialized[1];
        String encodedJweInitializationVector = deserialized[2];
        String encodedCipherText = deserialized[3];
        String encodedAuthenticationTag = deserialized[4];

        Cipher rsa15cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsa15cipher.init(Cipher.UNWRAP_MODE, ExampleRsaJwksFromJwe.APPENDIX_A_2.getPrivateKey());
        
        Base64Url base64Url = new Base64Url();
        byte[] encryptedKeyBytes = base64Url.base64UrlDecode(encodedJweEncryptedKey);
        System.out.println("encodedJweEncryptedKey: " +encodedJweEncryptedKey);

        Key key = rsa15cipher.unwrap(encryptedKeyBytes, AesKey.ALGORITHM, Cipher.SECRET_KEY);
        byte[] contentEncryptionKeyBytes = key.getEncoded();
        System.out.println("contentEncryptionKeyBytes getFormat() " + key.getFormat() + " getAlgorithm() " + key.getAlgorithm());

        System.out.println("contentEncryptionKeyBytes bytes " + Arrays.toString(contentEncryptionKeyBytes));
        System.out.println("contentEncryptionKeyBytes length " +contentEncryptionKeyBytes.length);

        byte[] hmacKeyBytes = ByteUtil.leftHalf(contentEncryptionKeyBytes);
        byte[] encKeyBytes = ByteUtil.rightHalf(contentEncryptionKeyBytes);

        Mac mac = MacUtil.getMac(MacUtil.HMAC_SHA256);
        mac.init(new HmacKey(hmacKeyBytes));

        byte[] cipherText = base64Url.base64UrlDecode(encodedCipherText);
        byte[] iv = base64Url.base64UrlDecode(encodedJweInitializationVector);

//        Let the Additional Authenticated Data encryption parameter be
//                the octets of the ASCII representation of the Encoded JWE Header
//                value.
        byte[] aad = StringUtil.getBytesAscii(encodedHeader);
        long numAadBits = ByteUtil.bitLength(aad);
        byte[] al = ByteUtil.getBytes(numAadBits);

        byte[] authenticationTagInput = ByteUtil.concat(aad, iv, cipherText, al);
        byte[] calculatedAuthenticationTag = mac.doFinal(authenticationTagInput);
        calculatedAuthenticationTag = ByteUtil.subArray(calculatedAuthenticationTag, 0, 16);
        byte[] authenticationTag = base64Url.base64UrlDecode(encodedAuthenticationTag);
        boolean tagMatch = ByteUtil.secureEquals(authenticationTag, calculatedAuthenticationTag);
        System.out.println(tagMatch);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, new AesKey(encKeyBytes), new IvParameterSpec(iv));

        byte[] bytes = cipher.doFinal(cipherText);
        String plainText = StringUtil.newStringUtf8(bytes);

        System.out.println(plainText);
    }


    public static void mainForCISPreso(String... args) throws JoseException
    {
        String claims = "{\n\"iss\":\"https:\\/\\/idp.example.com\",\n" +
                "\"exp\":1357255788,\n" +
                "\"aud\":\"https:\\/\\/sp.example.org\",\n" +
                "\"jti\":\"tmYvYVU2x8LvN72B5Q_EacH._5A\",\n" +
                "\"acr\":\"2\",\n" +
                "\"sub\":\"Brian\"\n}";

        Map<String, Object> claimsMap = JsonUtil.parseJson(claims);

        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload((claims));
        jws.setKeyIdHeaderValue("5");
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        jws.setKey(ExampleEcKeysFromJws.PRIVATE_256);

        String compactSerialization = jws.getCompactSerialization();
        System.out.println(compactSerialization);

        System.out.println(jws.getHeader());
        System.out.println(jws.getPayload());

        EcKeyUtil ku = new EcKeyUtil();
        JsonWebKey jwk4 = JsonWebKey.Factory.newJwk(ku.generateKeyPair(EllipticCurves.P256).getPublic());
        jwk4.setKeyId("4");
        JsonWebKey jwk5 = JsonWebKey.Factory.newJwk(ExampleEcKeysFromJws.PUBLIC_256);
        jwk5.setKeyId("5");
        JsonWebKey jwk6 = JsonWebKey.Factory.newJwk(ku.generateKeyPair(EllipticCurves.P256).getPublic());
        jwk6.setKeyId("6");
        JsonWebKeySet jwks = new JsonWebKeySet(jwk4, jwk5, jwk6);

        System.out.println(jwks.toJson());
    }

    public static void someJwkEcJwsStuff()
    {
//        EcKeyUtil ecku = new EcKeyUtil();
//
//        KeyPair keyPair = ecku.generateKeyPair(EllipticCurves.P256);
//        JsonWebKey jwk = JsonWebKey.Factory.newJwk(keyPair.getPublic());
//        jwk.setUse(Use.SIGNATURE);
//        jwk.setKeyId("the key");
//
//        KeyPair keyPair2 = ecku.generateKeyPair(EllipticCurves.P256);
//        JsonWebKey jwk2 = JsonWebKey.Factory.newJwk(keyPair2.getPublic());
//        jwk2.setUse(Use.SIGNATURE);
//        jwk2.setKeyId("other key");
//
//        JsonWebKeySet jwks = new JsonWebKeySet(jwk, jwk2);
//        System.out.println(jwks.toJson());
//
//        JsonWebSignature jws = new JsonWebSignature();
//        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
//        jws.setKeyIdHeaderValue("the key");
//        jws.setKey(keyPair.getPrivate());
//        jws.setPayload("PAYLOAD!");
//
//        String compactSerialization = jws.getCompactSerialization();
//
//        System.out.println(compactSerialization);

    }


//    public static void someJwksStuff()
//    {
//        String x509st = "-----BEGIN CERTIFICATE-----\n" +
//                    "MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYD\n" +
//                    "VQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcw\n" +
//                    "FQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIx\n" +

//                    "CzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5n\n" +
//                    "IElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEB\n" +
//                    "BQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtP\n" +
//                    "Dy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQv\n" +
//                    "zRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Ie\n" +
//                    "l+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWam\n" +
//                    "T3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG\n" +
//                    "9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWL\n" +
//                    "OgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEa\n" +
//                    "S9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaI\n" +
//                    "zmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR\n" +
//                    "+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA==\n" +
//                    "-----END CERTIFICATE-----\n";
//
//            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
//            Collection<? extends Certificate> collection = certFactory.generateCertificates(new ByteArrayInputStream(x509st.getBytes()));
//            Certificate next = collection.iterator().next();
//            PublicKey publicKey = next.getPublicKey();
//
//            JsonWebKey jsonWebKey = JsonWebKey.Factory.newJwk(publicKey);
//            jsonWebKey.setUse(Use.SIGNATURE);
//            jsonWebKey.setKeyId("1b94c");
//            JsonWebKeySet jwkset = new JsonWebKeySet(Arrays.asList(jsonWebKey));
//
//            System.out.println(jwkset.toJson());
//
//            String keyset = "{\"keys\":[\n" +
//                    " {\"kty\":\"RSA\",\n" +
//                    "  \"use\":\"sig\",\n" +
//                    "  \"kid\":\"1b94c\",\n" +
//                    "  \"n\":\"vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08PLbK_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0Qu2j8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxTWq4aYWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wgzjYQDwHMTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPdwS-qo-meMvVfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ\",\n" +
//                    "  \"e\":\"AQAB\"},\n" +
//                    " {\"kty\":\"PKIX\",\n" +
//                    "  \"use\":\"sig\",\n" +
//                    "  \"kid\":\"1b94c\",\n" +
//                    "  \"x5c\":[\"MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYD\n" +
//                    "VQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcw\n" +
//                    "FQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIx\n" +
//                    "CzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5n\n" +
//                    "IElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEB\n" +
//                    "BQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtP\n" +
//                    "Dy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQv\n" +
//                    "zRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Ie\n" +
//                    "l+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWam\n" +
//                    "T3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG\n" +
//                    "9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWL\n" +
//                    "OgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEa\n" +
//                    "S9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaI\n" +
//                    "zmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR\n" +
//                    "+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA==\"]}\n" +
//                    "]}";
//            Map<String, Object> stringObjectMap = JsonUtil.parseJson(keyset);
//            System.out.println(stringObjectMap);
//
//    }


//    public static void someExampleOrSomething()
//    {
        //        JsonWebSignature jws = new JsonWebSignature();
        //        Map payload =  new LinkedHashMap();
        //
        //        payload.put(ReservedClaimNames.ISSUER, "https://idp.example.com");
        //        IntDate date = IntDate.now();
        //        payload.put(ReservedClaimNames.EXPIRATION_TIME, date.getValue());
        //        payload.put(ReservedClaimNames.AUDIENCE, "https://sp.example.org");
        //        payload.put(ReservedClaimNames.JWT_ID, "tmYvYVU2x8LvN72B5Q_EacH._5A");
        //        payload.put("acr", "2");
        //        payload.put("sub", "Brian");
        //
        //        jws.setPayload(JSONObject.toJSONString(payload));
        //        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        //        jws.setKey(ExampleEcKeysFromJws.PRIVATE_256);
        //        System.out.println(jws.getCompactSerialization());
        //        System.out.println(jws.getHeader() + "." + jws.getPayload() + ".<SIGNATURE>");
        //        System.out.println();
//    }


//
//    public static void someECstuff() throws Exception
//    {
//        Signature signature = Signature.getInstance("SHA256withECDSA");
//        signature.initSign(ExampleEcKeysFromJws.PRIVATE_256);
//
//        // example from jws
//        String jwsSi = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
//        byte[] securedInputBytes = jwsSi.getBytes("ASCII");
//        signature.update(securedInputBytes);
//
//        byte[] realSig = signature.sign();
//        System.out.println("sig length in bytes " + realSig.length) ;
//        System.out.println("Signature: " + new BigInteger(1, realSig).toString(16));
//
//        Signature verifier = Signature.getInstance("SHA256withECDSA");
//        verifier.initVerify(ExampleEcKeysFromJws.PUBLIC_256);
//        verifier.update(securedInputBytes);
//        boolean b1 = verifier.verify(realSig);
//
//        System.out.println(b1);
//
//        Base64Url b64u = new Base64Url();
//        byte[] exampleSigBytes = b64u.base64UrlDecode("DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q");
//
//        byte[] encodedSig = EcdsaUsingShaAlgorithm.convertConcatenatedToDer(exampleSigBytes);
//
//        System.out.println("example sig length in bytes " + exampleSigBytes.length);
//
//        Signature verifier2 = Signature.getInstance("SHA256withECDSA");
//        verifier2.initVerify(ExampleEcKeysFromJws.PUBLIC_256);
//        verifier2.update(securedInputBytes);
//        boolean b2 = verifier2.verify(encodedSig);
//        System.out.println(b2);
//    }
//
//    public static void testJwsRsaExample() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException
//    {
//        String header = "{\"alg\":\"RS256\"}";
//        Base64 base64url = getBase64url();
//        String encodedHeader = base64url.encodeToString(StringUtils.getBytesUtf8(header));
//        System.out.println(encodedHeader);
//        System.out.println("eyJhbGciOiJSUzI1NiJ9");
//
//        String payload = getPayload();
//        String encodedPayload = base64url.encodeToString(StringUtils.getBytesUtf8(payload));
//
//        String securedInput = encodedHeader + DOT + encodedPayload;
//
//        System.out.println(securedInput);
//        String exampleSecInput = "eyJhbGciOiJSUzI1NiJ9" +
//                "." +
//                "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
//                "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
//        System.out.println(exampleSecInput);
//
//
//        int[] examplePrivateKxpo = {18, 174, 113, 164, 105, 205, 10, 43, 195, 126, 82,
//           108, 69, 0, 87, 31, 29, 97, 117, 29, 100, 233, 73,
//           112, 123, 98, 89, 15, 157, 11, 165, 124, 150, 60, 64,
//           30, 63, 207, 47, 44, 211, 189, 236, 136, 229, 3, 191,
//           198, 67, 155, 11, 40, 200, 47, 125, 55, 151, 103, 31,
//           82, 19, 238, 216, 193, 90, 37, 216, 213, 206, 160, 2,
//           94, 227, 171, 46, 139, 127, 121, 33, 111, 198, 59,
//           234, 86, 39, 83, 180, 6, 68, 198, 161, 81, 39, 217,
//           178, 149, 69, 64, 160, 187, 225, 163, 5, 86, 152, 45,
//           78, 159, 222, 95, 100, 37, 241, 77, 75, 113, 52, 65,
//           181, 93, 199, 59, 155, 74, 237, 204, 146, 172, 227,
//           146, 126, 55, 245, 125, 12, 253, 94, 117, 129, 250,
//           81, 44, 143, 73, 97, 169, 235, 11, 128, 248, 168, 7,
//           70, 114, 138, 85, 255, 70, 71, 31, 52, 37, 6, 59,
//           157, 83, 100, 47, 94, 222, 30, 132, 214, 19, 8, 26,
//           250, 92, 34, 208, 81, 40, 91, 214, 59, 148, 59, 86,
//           93, 137, 138, 5, 104, 84, 19, 229, 60, 60, 108, 101,
//           37, 255, 31, 227, 78, 61, 220, 112, 240, 213, 100,
//           80, 253, 164, 139, 161, 46, 16, 78, 157, 235, 159,
//           184, 24, 129, 225, 196, 189, 242, 93, 146, 71, 244,
//           80, 200, 101, 146, 121, 104, 231, 115, 52, 244, 65,
//           79, 117, 167, 80, 225, 57, 84, 110, 58, 138, 115,
//           157};
//
//        int [] exampleModulus = {161, 248, 22, 10, 226, 227, 201, 180, 101, 206, 141,
//            45, 101, 98, 99, 54, 43, 146, 125, 190, 41, 225, 240,
//            36, 119, 252, 22, 37, 204, 144, 161, 54, 227, 139,
//            217, 52, 151, 197, 182, 234, 99, 221, 119, 17, 230,
//            124, 116, 41, 249, 86, 176, 251, 138, 143, 8, 154,
//            220, 75, 105, 137, 60, 193, 51, 63, 83, 237, 208, 25,
//            184, 119, 132, 37, 47, 236, 145, 79, 228, 133, 119,
//            105, 89, 75, 234, 66, 128, 211, 44, 15, 85, 191, 98,
//            148, 79, 19, 3, 150, 188, 110, 155, 223, 110, 189,
//            210, 189, 163, 103, 142, 236, 160, 198, 104, 247, 1,
//            179, 141, 191, 251, 56, 200, 52, 44, 226, 254, 109,
//            39, 250, 222, 74, 90, 72, 116, 151, 157, 212, 185,
//            207, 154, 222, 196, 199, 91, 5, 133, 44, 44, 15, 94,
//            248, 165, 193, 117, 3, 146, 249, 68, 232, 237, 100,
//            193, 16, 198, 182, 71, 96, 154, 164, 120, 58, 235,
//            156, 108, 154, 215, 85, 49, 48, 80, 99, 139, 131,
//            102, 92, 111, 111, 122, 130, 163, 150, 112, 42, 31,
//            100, 27, 130, 211, 235, 242, 57, 34, 25, 73, 31, 182,
//            134, 135, 44, 87, 22, 245, 10, 248, 53, 141, 154,
//            139, 157, 23, 195, 64, 114, 143, 127, 135, 216, 154,
//            24, 216, 252, 171, 103, 173, 132, 89, 12, 46, 207,
//            117, 147, 57, 54, 60, 7, 3, 77, 111, 96, 111, 158,
//            33, 224, 84, 86, 202, 229, 233, 161};
//
//        BigInteger modulus = new BigInteger(1, getKey(exampleModulus));
//        System.out.println(modulus);
//        BigInteger privateExponent = new BigInteger(1, getKey(examplePrivateKxpo));
//        System.out.println(privateExponent);
//
//
//        KeySpec keySpec = new RSAPrivateKeySpec(modulus, privateExponent);
//        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
//
//        Signature signer = Signature.getInstance("SHA256withRSA");
//        signer.initSign(privateKey);
//        signer.update(StringUtils.getBytesUtf8(securedInput));
//        byte[] signatureBytes = signer.sign();
//
//        String b64sig = base64url.encodeToString(signatureBytes);
//        System.out.println(b64sig);
//
//        String exampleSig = "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7" +
//                "AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4" +
//                "BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K" +
//                "0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv" +
//                "hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB" +
//                "p0igcN_IoypGlUPQGe77Rw";
//        System.out.println(exampleSig);
//        System.out.println(exampleSig.equals(b64sig));
//    }
//
//
//    public static void testJwsHmacExample() throws NoSuchAlgorithmException, InvalidKeyException
//    {
//        Base64 b64url = getBase64url();
//
//        String header = "{\"typ\":\"JWT\"," + newline +
//                " \"alg\":\"HS256\"}";
//        System.out.println(header);
//
//
//        byte[] headerBytes = StringUtils.getBytesUtf8(header);
//        System.out.println(Arrays.toString(headerBytes));
//        String encodedHeader = b64url.encodeToString(headerBytes);
//
//        System.out.println(encodedHeader);
//        String exmpleEncodedHeader = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9";
//        System.out.println(exmpleEncodedHeader);
//        System.out.println(encodedHeader.equals(exmpleEncodedHeader));
//
//
//        byte[] bytes1 = b64url.decode(exmpleEncodedHeader);
//        String s1 = StringUtils.newStringUtf8(bytes1);
//        System.out.println(s1);
//
//        String payload = getPayload();
//
//
//        byte[] payloadBytes = StringUtils.getBytesUtf8(payload);
//        String encodedPayload = b64url.encodeToString(payloadBytes);
//
//        System.out.println(encodedPayload);
//        String exampleEncodedPayload = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
//        System.out.println(exampleEncodedPayload);
//        System.out.println(exampleEncodedPayload.equals(exampleEncodedPayload));
//
//        String securedInput = exmpleEncodedHeader + DOT + exampleEncodedPayload;
//        StringUtils.getBytesUtf8(securedInput);
//
//        int[] keyFromExample = {3, 35, 53, 75, 43, 15, 165, 188, 131, 126, 6, 101, 119, 123, 166,
//                       143, 90, 179, 40, 230, 240, 84, 201, 40, 169, 15, 132, 178, 210, 80,
//                       46, 191, 211, 251, 90, 146, 210, 6, 71, 239, 150, 138, 180, 195, 119,
//                       98, 61, 34, 61, 46, 33, 114, 5, 46, 79, 8, 192, 205, 154, 245, 103,
//                       208, 128, 163};
//
//        byte[] keyBytes = getKey(keyFromExample);
//
//        System.out.println(Arrays.toString(keyBytes));
//
//        String jceAlgo = "HMACSHA256";
//        Mac mac = Mac.getInstance(jceAlgo);
//        Key key = new SecretKeySpec(keyBytes, jceAlgo);
//        mac.init(key);
//
//        byte[] macBytes = mac.doFinal(StringUtils.getBytesUtf8(securedInput));
//        String sigValue = b64url.encodeToString(macBytes);
//        System.out.println(sigValue);
//        String exmpaleSigValue = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
//        System.out.println(exmpaleSigValue);
//        System.out.println(exmpaleSigValue.equals(sigValue));
//
//        String jws = encodedHeader + DOT + encodedPayload + DOT + sigValue;
//
//        String exampleJWS = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
//                "." +
//                "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
//                "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
//                "." +
//                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
//
//        System.out.println(jws);
//        System.out.println(exampleJWS);
//        System.out.println(exampleJWS.equals(jws));
//    }
//
//    private static String getPayload()
//    {
//        return "{\"iss\":\"joe\"," + newline + " \"exp\":1300819380," + newline +" \"http://example.com/is_root\":true}";
//    }
//
//    private static Base64 getBase64url()
//    {
//        return new Base64(-1, null, true);
//    }
//
//    private static byte[] getKey(int[] keyFromExample)
//    {
//        return ByteUtil.convertUnsignedToSignedTwosComp(keyFromExample);
//    }
//
//    private void someHexKeyThingForTesting() throws JoseException
//    {
//        String myHexing;
//
//        String jwks = "{\"keys\":[{\"alg\":\"RSA\",\"use\":\"sig\",\"kid\":\"5\",\"mod\":\"jEEnYC3tBKkYVRY7DAzWxIjxjptoKlm_GfIO2WbRIudVdS-vfr9HMEO2q3-XO10a8MQCFHQOyOdQdhtGsMyWrXbdfV6ivfPM7_2MO1UuYgV2tDhLzjjShzeMkomrsB_nAWtX8Qun1XsRBu_GIdJbd4WMoTbNVaaAf1-U8ieHDNE\",\"exp\":\"AQAB\"},{\"alg\":\"RSA\",\"use\":\"sig\",\"kid\":\"4\",\"mod\":\"6cKl2TEtFUfBs4zZCatIov1F7SDu_0azkbKzG-0HhiFyHsGZeP4EtHH9tXEJcKNLxZXeFCO9yK_n6LS4KiH87fRYAs6aHiNHdaPWo5D4kdiYG-HNAEMqJzWR9eykUomuUZRe6fiKLOBcgdWjstB7I5PAqFy75RXDLqFuRPDWub8\",\"exp\":\"AQAB\"},{\"alg\":\"RSA\",\"use\":\"sig\",\"kid\":\"3\",\"mod\":\"h7Jep0xSV6s-fZoHzQuZGT5g_I6q4chSrO0-yxYMehbmds9JFoJxQ2lcBnhkl8C4QudNk93Nyp_VGV33sytW7-22JpN2GFrxI80xzbZlZ7B1pxAZdP74C27YFJEBnwineiLowlHjc0OFQ-gwso6MYzwxV8NttwIDq4tBqbs1pxE\",\"exp\":\"AQAB\"},{\"alg\":\"RSA\",\"use\":\"sig\",\"kid\":\"2\",\"mod\":\"ktR38dP3vITaViAE_Wg4YX0CApH40QvtXKea-1GSsW8Yl1VxIq_dOcZPKgLLWm9is5g9WZuCYj3sRVfrRmKXoN0qjUX-ZC-L4oxMJzNMGIZ93XiiKC1bdMnHXhdkRhZB5M_-qlx5Cmw69qeQ_wuHJwV4hDjbQeUcfoZySCppfNM\",\"exp\":\"AQAB\"},{\"alg\":\"RSA\",\"use\":\"sig\",\"kid\":\"1\",\"mod\":\"y2ZGB-Ol6kmpFqWxc02xrjocp9VS9JsstaZl6Gy9hDmKXkkuKnap4hcWcHfF2PK0uLMJYUE_3se1dNBhR3M2ByOajHiSBGj_y_FYiTdjHb2bpkAJQ7wVT9ncT_Fx7V_kYvIevy1NBCr47bwqz4WJcUyZbHXFFoaOYnWHBVyjUl0\",\"exp\":\"AQAB\"},{\"alg\":\"RSA\",\"use\":\"sig\",\"kid\":\"0\",\"mod\":\"sjMKXtiyCUz6kAT9H9Ve0cHnWxJFN9d_eHNtk318QsJqt86BfhTlpdY7DbE7M0MVyVXIMTjXUDHnvZ4tCDXB3Q\",\"exp\":\"AQAB\"}]}";
//        JsonWebKeySet jwkset = new JsonWebKeySet(jwks);
//        JsonWebKey webKey = jwkset.findJsonWebKey("4", null, null, null);
//        RsaJsonWebKey rsaWebKey = (RsaJsonWebKey) webKey;
//
//        myHexing = Hex.encodeHexString(BigEndianBigInteger.toByteArray(rsaWebKey.getRSAPublicKey().getModulus()));
//        System.out.println(myHexing);
//
//        myHexing = Hex.encodeHexString(BigEndianBigInteger.toByteArray(rsaWebKey.getRSAPublicKey().getPublicExponent()));
//        System.out.println(myHexing);
//    }
//
//    public void pkixJwkExampleCheck() throws JoseException
//    {
//        Map<String, Object> parsed = JsonUtil.parseJson("{\"keys\":[\n" +
//                " {\"kty\":\"PKIX\",\n" +
//                "  \"x5c\":[\n" +
//                "   \"MIIE3jCCA8agAwIBAgICAwEwDQYJKoZIhvcNAQEFBQAwYzELMAkGA1UEBhMCVVM\n" +
//                "   xITAfBgNVBAoTGFRoZSBHbyBEYWRkeSBHcm91cCwgSW5jLjExMC8GA1UECxMoR2\n" +
//                "   8gRGFkZHkgQ2xhc3MgMiBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0wNjExM\n" +
//                "   TYwMTU0MzdaFw0yNjExMTYwMTU0MzdaMIHKMQswCQYDVQQGEwJVUzEQMA4GA1UE\n" +
//                "   CBMHQXJpem9uYTETMBEGA1UEBxMKU2NvdHRzZGFsZTEaMBgGA1UEChMRR29EYWR\n" +
//                "   keS5jb20sIEluYy4xMzAxBgNVBAsTKmh0dHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYW\n" +
//                "   RkeS5jb20vcmVwb3NpdG9yeTEwMC4GA1UEAxMnR28gRGFkZHkgU2VjdXJlIENlc\n" +
//                "   nRpZmljYXRpb24gQXV0aG9yaXR5MREwDwYDVQQFEwgwNzk2OTI4NzCCASIwDQYJ\n" +
//                "   KoZIhvcNAQEBBQADggEPADCCAQoCggEBAMQt1RWMnCZM7DI161+4WQFapmGBWTt\n" +
//                "   wY6vj3D3HKrjJM9N55DrtPDAjhI6zMBS2sofDPZVUBJ7fmd0LJR4h3mUpfjWoqV\n" +
//                "   Tr9vcyOdQmVZWt7/v+WIbXnvQAjYwqDL1CBM6nPwT27oDyqu9SoWlm2r4arV3aL\n" +
//                "   GbqGmu75RpRSgAvSMeYddi5Kcju+GZtCpyz8/x4fKL4o/K1w/O5epHBp+YlLpyo\n" +
//                "   7RJlbmr2EkRTcDCVw5wrWCs9CHRK8r5RsL+H0EwnWGu1NcWdrxcx+AuP7q2BNgW\n" +
//                "   JCJjPOq8lh8BJ6qf9Z/dFjpfMFDniNoW1fho3/Rb2cRGadDAW/hOUoz+EDU8CAw\n" +
//                "   EAAaOCATIwggEuMB0GA1UdDgQWBBT9rGEyk2xF1uLuhV+auud2mWjM5zAfBgNVH\n" +
//                "   SMEGDAWgBTSxLDSkdRMEXGzYcs9of7dqGrU4zASBgNVHRMBAf8ECDAGAQH/AgEA\n" +
//                "   MDMGCCsGAQUFBwEBBCcwJTAjBggrBgEFBQcwAYYXaHR0cDovL29jc3AuZ29kYWR\n" +
//                "   keS5jb20wRgYDVR0fBD8wPTA7oDmgN4Y1aHR0cDovL2NlcnRpZmljYXRlcy5nb2\n" +
//                "   RhZGR5LmNvbS9yZXBvc2l0b3J5L2dkcm9vdC5jcmwwSwYDVR0gBEQwQjBABgRVH\n" +
//                "   SAAMDgwNgYIKwYBBQUHAgEWKmh0dHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYWRkeS5j\n" +
//                "   b20vcmVwb3NpdG9yeTAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQEFBQADggE\n" +
//                "   BANKGwOy9+aG2Z+5mC6IGOgRQjhVyrEp0lVPLN8tESe8HkGsz2ZbwlFalEzAFPI\n" +
//                "   UyIXvJxwqoJKSQ3kbTJSMUA2fCENZvD117esyfxVgqwcSeIaha86ykRvOe5GPLL\n" +
//                "   5CkKSkB2XIsKd83ASe8T+5o0yGPwLPk9Qnt0hCqU7S+8MxZC9Y7lhyVJEnfzuz9\n" +
//                "   p0iRFEUOOjZv2kWzRaJBydTXRE4+uXR21aITVSzGh6O1mawGhId/dQb8vxRMDsx\n" +
//                "   uxN89txJx9OjxUUAiKEngHUuHqDTMBqLdElrRhjZkAzVvb3du6/KFUJheqwNTrZ\n" +
//                "   EjYx8WnM25sgVjOuH0aBsXBTWVU+4=\",\n" +
//                "   \"MIIE+zCCBGSgAwIBAgICAQ0wDQYJKoZIhvcNAQEFBQAwgbsxJDAiBgNVBAcTG1Z\n" +
//                "   hbGlDZXJ0IFZhbGlkYXRpb24gTmV0d29yazEXMBUGA1UEChMOVmFsaUNlcnQsIE\n" +
//                "   luYy4xNTAzBgNVBAsTLFZhbGlDZXJ0IENsYXNzIDIgUG9saWN5IFZhbGlkYXRpb\n" +
//                "   24gQXV0aG9yaXR5MSEwHwYDVQQDExhodHRwOi8vd3d3LnZhbGljZXJ0LmNvbS8x\n" +
//                "   IDAeBgkqhkiG9w0BCQEWEWluZm9AdmFsaWNlcnQuY29tMB4XDTA0MDYyOTE3MDY\n" +
//                "   yMFoXDTI0MDYyOTE3MDYyMFowYzELMAkGA1UEBhMCVVMxITAfBgNVBAoTGFRoZS\n" +
//                "   BHbyBEYWRkeSBHcm91cCwgSW5jLjExMC8GA1UECxMoR28gRGFkZHkgQ2xhc3MgM\n" +
//                "   iBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTCCASAwDQYJKoZIhvcNAQEBBQADggEN\n" +
//                "   ADCCAQgCggEBAN6d1+pXGEmhW+vXX0iG6r7d/+TvZxz0ZWizV3GgXne77ZtJ6XC\n" +
//                "   APVYYYwhv2vLM0D9/AlQiVBDYsoHUwHU9S3/Hd8M+eKsaA7Ugay9qK7HFiH7Eux\n" +
//                "   6wwdhFJ2+qN1j3hybX2C32qRe3H3I2TqYXP2WYktsqbl2i/ojgC95/5Y0V4evLO\n" +
//                "   tXiEqITLdiOr18SPaAIBQi2XKVlOARFmR6jYGB0xUGlcmIbYsUfb18aQr4CUWWo\n" +
//                "   riMYavx4A6lNf4DD+qta/KFApMoZFv6yyO9ecw3ud72a9nmYvLEHZ6IVDd2gWMZ\n" +
//                "   Eewo+YihfukEHU1jPEX44dMX4/7VpkI+EdOqXG68CAQOjggHhMIIB3TAdBgNVHQ\n" +
//                "   4EFgQU0sSw0pHUTBFxs2HLPaH+3ahq1OMwgdIGA1UdIwSByjCBx6GBwaSBvjCBu\n" +
//                "   zEkMCIGA1UEBxMbVmFsaUNlcnQgVmFsaWRhdGlvbiBOZXR3b3JrMRcwFQYDVQQK\n" +
//                "   Ew5WYWxpQ2VydCwgSW5jLjE1MDMGA1UECxMsVmFsaUNlcnQgQ2xhc3MgMiBQb2x\n" +
//                "   pY3kgVmFsaWRhdGlvbiBBdXRob3JpdHkxITAfBgNVBAMTGGh0dHA6Ly93d3cudm\n" +
//                "   FsaWNlcnQuY29tLzEgMB4GCSqGSIb3DQEJARYRaW5mb0B2YWxpY2VydC5jb22CA\n" +
//                "   QEwDwYDVR0TAQH/BAUwAwEB/zAzBggrBgEFBQcBAQQnMCUwIwYIKwYBBQUHMAGG\n" +
//                "   F2h0dHA6Ly9vY3NwLmdvZGFkZHkuY29tMEQGA1UdHwQ9MDswOaA3oDWGM2h0dHA\n" +
//                "   6Ly9jZXJ0aWZpY2F0ZXMuZ29kYWRkeS5jb20vcmVwb3NpdG9yeS9yb290LmNybD\n" +
//                "   BLBgNVHSAERDBCMEAGBFUdIAAwODA2BggrBgEFBQcCARYqaHR0cDovL2NlcnRpZ\n" +
//                "   mljYXRlcy5nb2RhZGR5LmNvbS9yZXBvc2l0b3J5MA4GA1UdDwEB/wQEAwIBBjAN\n" +
//                "   BgkqhkiG9w0BAQUFAAOBgQC1QPmnHfbq/qQaQlpE9xXUhUaJwL6e4+PrxeNYiY+\n" +
//                "   Sn1eocSxI0YGyeR+sBjUZsE4OWBsUs5iB0QQeyAfJg594RAoYC5jcdnplDQ1tgM\n" +
//                "   QLARzLrUc+cb53S8wGd9D0VmsfSxOaFIqII6hR8INMqzW/Rn453HWkrugp++85j\n" +
//                "   09VZw==\",\n" +
//                "   \"MIIC5zCCAlACAQEwDQYJKoZIhvcNAQEFBQAwgbsxJDAiBgNVBAcTG1ZhbGlDZXJ\n" +
//                "   0IFZhbGlkYXRpb24gTmV0d29yazEXMBUGA1UEChMOVmFsaUNlcnQsIEluYy4xNT\n" +
//                "   AzBgNVBAsTLFZhbGlDZXJ0IENsYXNzIDIgUG9saWN5IFZhbGlkYXRpb24gQXV0a\n" +
//                "   G9yaXR5MSEwHwYDVQQDExhodHRwOi8vd3d3LnZhbGljZXJ0LmNvbS8xIDAeBgkq\n" +
//                "   hkiG9w0BCQEWEWluZm9AdmFsaWNlcnQuY29tMB4XDTk5MDYyNjAwMTk1NFoXDTE\n" +
//                "   5MDYyNjAwMTk1NFowgbsxJDAiBgNVBAcTG1ZhbGlDZXJ0IFZhbGlkYXRpb24gTm\n" +
//                "   V0d29yazEXMBUGA1UEChMOVmFsaUNlcnQsIEluYy4xNTAzBgNVBAsTLFZhbGlDZ\n" +
//                "   XJ0IENsYXNzIDIgUG9saWN5IFZhbGlkYXRpb24gQXV0aG9yaXR5MSEwHwYDVQQD\n" +
//                "   ExhodHRwOi8vd3d3LnZhbGljZXJ0LmNvbS8xIDAeBgkqhkiG9w0BCQEWEWluZm9\n" +
//                "   AdmFsaWNlcnQuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDOOnHK5a\n" +
//                "   vIWZJV16vYdA757tn2VUdZZUcOBVXc65g2PFxTXdMwzzjsvUGJ7SVCCSRrCl6zf\n" +
//                "   N1SLUzm1NZ9WlmpZdRJEy0kTRxQb7XBhVQ7/nHk01xC+YDgkRoKWzk2Z/M/VXwb\n" +
//                "   P7RfZHM047QSv4dk+NoS/zcnwbNDu+97bi5p9wIDAQABMA0GCSqGSIb3DQEBBQU\n" +
//                "   AA4GBADt/UG9vUJSZSWI4OB9L+KXIPqeCgfYrx+jFzug6EILLGACOTb2oWH+heQ\n" +
//                "   C1u+mNr0HZDzTuIYEZoDJJKPTEjlbVUjP9UNV+mWwD5MlM/Mtsq2azSiGM5bUMM\n" +
//                "   j4QssxsodyamEwCW/POuZ6lcg5Ktz885hZo+L7tdEy8W9ViH0Pd\"],\n" +
//                "  \"use\":\"sign\",\n" +
//                "  \"kid\":\"somekey\"}]\n" +
//                "}");
//
//    }

}
