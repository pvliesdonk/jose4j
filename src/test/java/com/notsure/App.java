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

package com.notsure;

import org.jose4j.base64url.Base64;
import org.jose4j.base64url.Base64Url;
import org.jose4j.http.Get;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.*;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaimsSet;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.keys.BigEndianBigInteger;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.keys.PbkdfKey;
import org.jose4j.keys.X509Util;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.StringUtil;
import org.jose4j.zip.CompressionAlgorithm;
import org.jose4j.zip.CompressionAlgorithmIdentifiers;
import org.junit.Test;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedList;
import java.util.List;

/**
 * Just a sandbox for messing with stuff
 */
public class App 
{
    public void smoething() throws IOException, JoseException
    {
        HttpsJsonWebKeySet hjwks = new HttpsJsonWebKeySet("https://www.googleapis.com/oauth2/v2/certs");
        List<JsonWebKey> jsonWebKeys = hjwks.getJsonWebKeys();
        System.out.println(jsonWebKeys);
        VerificationJwkSelector vjs = new VerificationJwkSelector();
        JsonWebSignature jws = new JsonWebSignature();
        jws.setKeyIdHeaderValue("8472c6590b1778fe529c1bd3a8f181cc2af4b200"); // this changes...
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        JsonWebKey select = vjs.select(jws, jsonWebKeys);
        System.out.println(select);
    }

    public void testPFC() throws Exception
    {
        X509Util x509Util = new X509Util();
        X509Certificate certificate = x509Util.fromBase64Der(
                "MIICUDCCAbkCBETczdcwDQYJKoZIhvcNAQEFBQAwbzELMAkGA1UEBhMCVVMxCzAJ\n" +
                "BgNVBAgTAkNPMQ8wDQYDVQQHEwZEZW52ZXIxFTATBgNVBAoTDFBpbmdJZGVudGl0\n" +
                "eTEXMBUGA1UECxMOQnJpYW4gQ2FtcGJlbGwxEjAQBgNVBAMTCWxvY2FsaG9zdDAe\n" +
                "Fw0wNjA4MTExODM1MDNaFw0zMzEyMjcxODM1MDNaMG8xCzAJBgNVBAYTAlVTMQsw\n" +
                "CQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRUwEwYDVQQKEwxQaW5nSWRlbnRp\n" +
                "dHkxFzAVBgNVBAsTDkJyaWFuIENhbXBiZWxsMRIwEAYDVQQDEwlsb2NhbGhvc3Qw\n" +
                "gZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJLrpeiY/Ai2gGFxNY8Tm/QSO8qg\n" +
                "POGKDMAT08QMyHRlxW8fpezfBTAtKcEsztPzwYTLWmf6opfJT+5N6cJKacxWchn/\n" +
                "dRrzV2BoNuz1uo7wlpRqwcaOoi6yHuopNuNO1ms1vmlv3POq5qzMe6c1LRGADyZh\n" +
                "i0KejDX6+jVaDiUTAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAMojbPEYJiIWgQzZc\n" +
                "QJCQeodtKSJl5+lA8MWBBFFyZmvZ6jUYglIQdLlc8Pu6JF2j/hZEeTI87z/DOT6U\n" +
                "uqZA83gZcy6re4wMnZvY2kWX9CsVWDCaZhnyhjBNYfhcOf0ZychoKShaEpTQ5UAG\n" +
                "wvYYcbqIWC04GAZYVsZxlPl9hoA=\n");


        String location = "https://localhost:9031/pf/JWKS";

        Get get = new Get();
        get.setTrustedCertificates(certificate);
        get.setReadTimeout(100);
        get.setRetries(5);
        get.setProgressiveRetryWait(true);
        get.setInitialRetryWaitTime(500);

        final HttpsJsonWebKeySet httpsJwks = new HttpsJsonWebKeySet(location);
        httpsJwks.setSimpleHttpGet(get);
        httpsJwks.setDefaultCacheDuration(4);

        int threads = 10;
        for (int i = 0; i < threads; i++)
        {
            Runnable r = new Runnable()
            {
                public void run()
                {

                    while (true)
                    {
                        try
                        {
                            try
                            {
                                long millis = (long) (Math.random() * 100);
                                Thread.sleep(millis);
                            }
                            catch (InterruptedException e)
                            {
                                e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
                            }
                            httpsJwks.getJsonWebKeys();

                        }
                        catch (JoseException | IOException e)
                        {
                            throw new RuntimeException("pow!", e);
                        }
                    }
                }

            };

            Thread t = new Thread(r);
            t.setDaemon(false);
            t.start();
        }


    }

    public static void main(String... meh) throws Exception
    {
       new App().testPFC();
//       String json = "     {\n" +
//               "      \"kty\": \"RSA\",\n" +
//               "      \"n\": \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt\n" +
//               "            VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6\n" +
//               "            4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD\n" +
//               "            W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9\n" +
//               "            1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH\n" +
//               "            aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\",\n" +
//               "      \"e\": \"AQAB\",\n" +
//               "      \"alg\": \"RS256\",\n" +
//               "      \"kid\": \"2011-04-29\"\n" +
//               "     }";
//
//        RsaJsonWebKey jwk = (RsaJsonWebKey)PublicJsonWebKey.Factory.newPublicJwk(json);
//
//        String template = "{\"e\":\"%s\",\"kty\":\"RSA\",\"n\":\"%s\"}";
//        RSAPublicKey rsaPublicKey = jwk.getRsaPublicKey();
//        String e = BigEndianBigInteger.toBase64Url(rsaPublicKey.getPublicExponent());
//        String n = BigEndianBigInteger.toBase64Url(rsaPublicKey.getModulus());
//        String formated = String.format(template, e, n);
//        byte[] bytesUtf8 = StringUtil.getBytesUtf8(formated);
//        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
//        byte[] digest = sha256.digest(bytesUtf8);
//        String encode = Base64Url.encode(digest);
//        System.out.println(encode);
//        System.out.println("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs".equals(encode));

//        JwtClaimsSet jcs = new JwtClaimsSet();
//        jcs.setIssuer("usa");
//        jcs.setAudience("canada");
//        jcs.setExpirationTimeMinutesInTheFuture(30);
//        jcs.setClaim("message", "eh");
//        String claims = jcs.toJson();
//        JsonWebSignature jws = new JsonWebSignature();
//        jws.setPayload(claims);
//        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
//        OctetSequenceJsonWebKey macKey = OctJwkGenerator.generateJwk(256);
//        jws.setKey(macKey.getKey());
//        String jwscs = jws.getCompactSerialization();
//        System.out.println(claims);
//        System.out.println(macKey.toJson(JsonWebKey.OutputControlLevel.INCLUDE_SYMMETRIC));
//        System.out.println(jwscs);
//
//        OctetSequenceJsonWebKey wrapKey = OctJwkGenerator.generateJwk(128);
//
//        JsonWebEncryption jwe = new JsonWebEncryption();
//        jwe.setPayload(jwscs);
//        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.A128KW);
//        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
//        System.out.println(wrapKey.toJson(JsonWebKey.OutputControlLevel.INCLUDE_SYMMETRIC));
//        jwe.setKey(wrapKey.getKey());
//        jwe.setHeader(HeaderParameterNames.CONTENT_TYPE, "JWT");
//        System.out.println(jwe.getCompactSerialization());
//
//        jwe = new JsonWebEncryption();
//        jwe.setHeader(HeaderParameterNames.ZIP, CompressionAlgorithmIdentifiers.DEFLATE);
//        jwe.setPayload(jwscs);
//        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.A128KW);
//        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
//        System.out.println(wrapKey.toJson(JsonWebKey.OutputControlLevel.INCLUDE_SYMMETRIC));
//        jwe.setKey(wrapKey.getKey());
//        jwe.setHeader(HeaderParameterNames.CONTENT_TYPE, "JWT");
//        System.out.println(jwe.getCompactSerialization());


//String jwksJson =
//    "{\"keys\":[\n" +
//    " {\"kty\":\"EC\",\n\"kid\":\"4\",\n" +
//    "  \"x\":\"LX-7aQn7RAx3jDDTioNssbODUfED_6XvZP8NsGzMlRo\", \n" +
//    "  \"y\":\"dJbHEoeWzezPYuz6qjKJoRVLks7X8-BJXbewfyoJQ-A\",\n" +
//    "  \"crv\":\"P-256\"},\n" +
//    " {\"kty\":\"EC\",\n\"kid\":\"5\",\n" +
//    "  \"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\n" +
//    "  \"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\",\n" +
//    "  \"crv\":\"P-256\"},\n" +
//    " {\"kty\":\"EC\",\n\"kid\":\"6\",\n" +
//    "  \"x\":\"J8z237wci2YJAzArSdWIj4OgrOCCfuZ18WI77jsiS00\",\n" +
//    "  \"y\":\"5tTxvax8aRMMJ4unKdKsV0wcf3pOI3OG771gOa45wBU\",\n" +
//    "  \"crv\":\"P-256\"}\n" +
//    "]}";
//
//JsonWebKeySet jwks = new JsonWebKeySet(jwksJson);
//JsonWebKey jwk = jwks.findJsonWebKey("5", null, null, null);
//System.out.println(jwk.getKey());



//List<JsonWebKey> jwkList = new LinkedList<>();
//for (int kid = 4; kid < 7; kid++)
//{
//    JsonWebKey jwk = EcJwkGenerator.generateJwk(EllipticCurves.P256);
//    jwk.setKeyId(String.valueOf(kid));
//    jwkList.add(jwk);
//}
//JsonWebKeySet jwks = new JsonWebKeySet(jwkList);
//System.out.println(jwks.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY));

//JsonWebEncryption jwe = new JsonWebEncryption();
//jwe.setPayload("I actually really like Canada");
//jwe.setKey(new PbkdfKey("don't-tell-p@ul|pam!"));
//jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.PBES2_HS256_A128KW);
//jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
//String compactSerialization = jwe.getCompactSerialization();
//
//System.out.println(compactSerialization);


//        String compactSerialization =
//            "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwicDJjIjo4MTkyLCJwMnMiOiJRa2JMUW5pS0xVVFFWUDRsIn0." +
//            "g7s-MxHFn5WHCfO33hgWYiAtH1lB83TnufWoaFIEujEYb14pqeH9Mg." +
//            "6h172lww9VqemjMQMaVPdg." +
//            "YMg_F8aoT3ZByou3CURhKzaGX1nc5QJDo3cWyUSyow0." +
//            "Ie4iYLbdQCqwMWJf37rEZg";
//
//        JsonWebEncryption jwe = new JsonWebEncryption();
//        jwe.setCompactSerialization(compactSerialization);
//        jwe.setKey(new PbkdfKey("don't-tell-p@ul|pam!"));
//        String payload = jwe.getPayload();
//
//        System.out.println(payload);


//
//JsonWebKey jwk = JsonWebKey.Factory.newJwk("{\"kty\":\"EC\"," +
//    "\"kid\":\"my-first-key\"," +
//    "\"x\":\"xlKTWTx76fl9OZou4LHpDc3oHLC_vm-db7mdsFvO1JQ\"," +
//    "\"y\":\"3jXBG649Uqf7pf8RHO_jcJ8Jrhy23hjD933i6QEVNkk\"," +
//    "\"crv\":\"P-256\"}");
//
//String compactSerialization =
//    "eyJhbGciOiJFUzI1NiIsImtpZCI6Im15LWZpcnN0LWtleSJ9." +
//    "VVNBICMxIQ." +
//    "QJGB_sHj-w3yCBunJs2wxKgvZgG2Hq9PA-TDQEbNdTm2Wnj2sUSrBKZJAUREzF1FF25BbrgyohbKdGE1cB-hrA";
//
//
//JsonWebSignature jws = new JsonWebSignature();
//jws.setCompactSerialization(compactSerialization);
//jws.setKey(jwk.getKey());
//String payload = jws.getPayload();
//
//System.out.println(payload);


//
//PublicJsonWebKey jwk = EcJwkGenerator.generateJwk(EllipticCurves.P256);
//jwk.setKeyId("my-first-key");
//
//JsonWebSignature jws = new JsonWebSignature();
//jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
//jws.setPayload("USA #1!");
//jws.setKey(jwk.getPrivateKey());
//jws.setKeyIdHeaderValue(jwk.getKeyId());
//String compactSerialization = jws.getCompactSerialization();
//
//System.out.println(compactSerialization);
//
//
//        System.out.println(jws.getHeaders().getFullHeaderAsJsonString());
//        System.out.println(jwk.toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE));
//        System.out.println(jwk.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY));
    }

    public static void dumpProviderInfo()
    {
        String version = System.getProperty("java.version");
        String vendor = System.getProperty("java.vendor");
        String home = System.getProperty("java.home");
        System.out.println("Java "+version+" from "+vendor+" at "+home+"");
        for (Provider provider : Security.getProviders())
        {
            System.out.println("Provider: " + provider.getName());
            for (Provider.Service service : provider.getServices())
            {
                System.out.println(" -> Algorithm: " + service.getAlgorithm());
            }
        }
    }

}
