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
import java.security.PublicKey;

/**
 */
public class EcdhKeyAgreementAlgorithmTest extends TestCase
{
    public void testExampleJwaAppendixD() throws JoseException
    {
        // testing http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-14#appendix-D
        // but the output doesn't match
        // though a different implementer got the same result as me
        // http://lists.openid.net/pipermail/openid-specs-ab/Week-of-Mon-20130805/003869.html
        // and that's what this is testing for now
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
}
