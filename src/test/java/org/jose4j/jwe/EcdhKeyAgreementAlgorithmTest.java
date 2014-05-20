package org.jose4j.jwe;

import junit.framework.TestCase;
import org.jose4j.base64url.Base64Url;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.jwx.Headers;
import org.jose4j.keys.AesKey;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.JoseException;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 */
public class EcdhKeyAgreementAlgorithmTest extends TestCase
{
    public void testExampleJwaAppendixC() throws JoseException
    {
        // testing http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-17#appendix-D
        // now http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-26#appendix-C
        String receiverJwkJson = "\n{\"kty\":\"EC\",\n" +
                " \"crv\":\"P-256\",\n" +
                " \"x\":\"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ\",\n" +
                " \"y\":\"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck\",\n" +
                " \"d\":\"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw\"\n" +
                "}";
        PublicJsonWebKey receiverJwk = PublicJsonWebKey.Factory.newPublicJwk(receiverJwkJson);

        String ephemeralJwkJson = "\n{\"kty\":\"EC\",\n" +
                " \"crv\":\"P-256\",\n" +
                " \"x\":\"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0\",\n" +
                " \"y\":\"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps\",\n" +
                " \"d\":\"0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo\"\n" +
                "}";

        PublicJsonWebKey ephemeralJwk = PublicJsonWebKey.Factory.newPublicJwk(ephemeralJwkJson);

        Headers headers = new Headers();

        headers.setStringHeaderValue(HeaderParameterNames.ALGORITHM, KeyManagementAlgorithmIdentifiers.ECDH_ES);
        headers.setStringHeaderValue(HeaderParameterNames.ENCRYPTION_METHOD, ContentEncryptionAlgorithmIdentifiers.AES_128_GCM);

        headers.setStringHeaderValue(HeaderParameterNames.AGREEMENT_PARTY_U_INFO, "QWxpY2U");
        headers.setStringHeaderValue(HeaderParameterNames.AGREEMENT_PARTY_V_INFO, "Qm9i");

        headers.setJwkHeaderValue(HeaderParameterNames.EPHEMERAL_PUBLIC_KEY, ephemeralJwk);

        EcdhKeyAgreementAlgorithm ecdhKeyAgreementAlgorithm = new EcdhKeyAgreementAlgorithm();

        ContentEncryptionKeyDescriptor cekDesc = new ContentEncryptionKeyDescriptor(ByteUtil.byteLength(128), AesKey.ALGORITHM);

        PublicKey pubKey = receiverJwk.getPublicKey();
        ContentEncryptionKeys contentEncryptionKeys = ecdhKeyAgreementAlgorithm.manageForEncrypt(pubKey, cekDesc, headers, ephemeralJwk);

        assertTrue(contentEncryptionKeys.getEncryptedKey().length == 0);
        Base64Url base64Url = new Base64Url();
        assertEquals("VqqN6vgjbSBcIijNcacQGg", base64Url.base64UrlEncode(contentEncryptionKeys.getContentEncryptionKey()));

        Headers receivedHeaders = new Headers();
        receivedHeaders.setFullHeaderAsJsonString(headers.getFullHeaderAsJsonString());

        Key key = ecdhKeyAgreementAlgorithm.manageForDecrypt(receiverJwk.getPrivateKey(), null, cekDesc, receivedHeaders);
        assertEquals("VqqN6vgjbSBcIijNcacQGg", base64Url.base64UrlEncode(key.getEncoded()));
    }

        public void testDV256() throws JoseException
        {
        /*
            A working test w/ data produced by Dmitry Vsekhvalnov doing ECDH with P-256 + ConcatKDF to produce a 256 bit key
            ---
            Ok, data below. Everything base64url encoded. partyUInfo=partyVInfo=[0,0,0,0] in all samples.

            Curve P-256, 256 bit key (match to jose4j and to spec sample, provided as reference)

            X = BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk
            Y = g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU
            D = KpTnMOHEpskXvuXHFCfiRtGUHUZ9Dq5CCcZQ-19rYs4

            ephemeral X = UWlKW_GHsZa1ikOUPocsMi2pNh_1K2vhn6ZjJqALOK8
            ephemeral Y = n2oj0Z6EYgzRDmeROILD4fp2zAMGLQzmI8G1k5nsev0

            algId = AAAADUExMjhDQkMtSFMyNTY
            suppPubInfo = AAABAA

            derived key = bqXVMd1yd5E08Wy2T1U9m9Q5DEjj7-BYIyWUgazzZkA
         */

        String receiverJwkJson = "\n{\"kty\":\"EC\",\n" +
                " \"crv\":\"P-256\",\n" +
                " \"x\":\"BHId3zoDv6pDgOUh8rKdloUZ0YumRTcaVDCppUPoYgk\",\n" +
                " \"y\":\"g3QIDhaWEksYtZ9OWjNHn9a6-i_P9o5_NrdISP0VWDU\",\n" +
                " \"d\":\"KpTnMOHEpskXvuXHFCfiRtGUHUZ9Dq5CCcZQ-19rYs4\"\n" +
                "}";
        PublicJsonWebKey receiverJwk = PublicJsonWebKey.Factory.newPublicJwk(receiverJwkJson);

        String ephemeralJwkJson = "\n{\"kty\":\"EC\",\n" +
                " \"crv\":\"P-256\",\n" +
                " \"x\":\"UWlKW_GHsZa1ikOUPocsMi2pNh_1K2vhn6ZjJqALOK8\",\n" +
                " \"y\":\"n2oj0Z6EYgzRDmeROILD4fp2zAMGLQzmI8G1k5nsev0\"\n" +
                "}";

        PublicJsonWebKey ephemeralJwk = PublicJsonWebKey.Factory.newPublicJwk(ephemeralJwkJson);

        Headers headers = new Headers();

        headers.setStringHeaderValue(HeaderParameterNames.ALGORITHM, KeyManagementAlgorithmIdentifiers.ECDH_ES);
        headers.setStringHeaderValue(HeaderParameterNames.ENCRYPTION_METHOD, ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);

        headers.setJwkHeaderValue(HeaderParameterNames.EPHEMERAL_PUBLIC_KEY, ephemeralJwk);

        EcdhKeyAgreementAlgorithm ecdhKeyAgreementAlgorithm = new EcdhKeyAgreementAlgorithm();

        ContentEncryptionKeyDescriptor cekDesc = new ContentEncryptionKeyDescriptor(ByteUtil.byteLength(256), AesKey.ALGORITHM);

        Key derivedKey = ecdhKeyAgreementAlgorithm.manageForDecrypt(receiverJwk.getPrivateKey(), null, cekDesc, headers);
        assertEquals("bqXVMd1yd5E08Wy2T1U9m9Q5DEjj7-BYIyWUgazzZkA", Base64Url.encode(derivedKey.getEncoded()));
    }
}
