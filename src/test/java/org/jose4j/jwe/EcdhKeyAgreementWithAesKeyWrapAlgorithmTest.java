package org.jose4j.jwe;

import junit.framework.TestCase;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.lang.JoseException;

/**
 */
public class EcdhKeyAgreementWithAesKeyWrapAlgorithmTest extends TestCase
{
    public void testRoundTrip() throws JoseException
    {
        Log log = LogFactory.getLog(this.getClass());

        String algs[] = {KeyManagementAlgorithmIdentifiers.ECDH_ES_A128KW,
                         KeyManagementAlgorithmIdentifiers.ECDH_ES_A192KW,
                         KeyManagementAlgorithmIdentifiers.ECDH_ES_A256KW};

        String[] encs = {ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256,
                         ContentEncryptionAlgorithmIdentifiers.AES_192_CBC_HMAC_SHA_384,
                         ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512};

        for (String alg : algs)
        {
            for (String enc : encs)
            {
                JsonWebEncryption jwe = new JsonWebEncryption();

                String receiverJwkJson = "\n{\"kty\":\"EC\",\n" +
                        " \"crv\":\"P-256\",\n" +
                        " \"x\":\"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ\",\n" +
                        " \"y\":\"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck\",\n" +
                        " \"d\":\"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw\"\n" +
                        "}";
                PublicJsonWebKey receiverJwk = PublicJsonWebKey.Factory.newPublicJwk(receiverJwkJson);

                jwe.setAlgorithmHeaderValue(alg);
                jwe.setEncryptionMethodHeaderParameter(enc);
                String plaintext = "Gambling is illegal at Bushwood sir, and I never slice.";
                jwe.setPlaintext(plaintext);

                jwe.setKey(receiverJwk.getPublicKey());

                String compactSerialization = jwe.getCompactSerialization();

                log.debug("JWE w/ " + alg + " & " + enc +": " + compactSerialization);

                JsonWebEncryption receiverJwe = new JsonWebEncryption();
                receiverJwe.setCompactSerialization(compactSerialization);
                receiverJwe.setKey(receiverJwk.getPrivateKey());

                assertEquals(plaintext, receiverJwe.getPlaintextString());
            }
        }

    }
}
