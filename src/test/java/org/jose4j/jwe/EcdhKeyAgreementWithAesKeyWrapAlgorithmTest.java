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

package org.jose4j.jwe;

import junit.framework.TestCase;

import org.jose4j.jwa.AlgorithmFactory;
import org.jose4j.jwa.AlgorithmFactoryFactory;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.lang.JoseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 */
public class EcdhKeyAgreementWithAesKeyWrapAlgorithmTest extends TestCase
{
    private static final Logger log = LoggerFactory.getLogger(EcdhKeyAgreementWithAesKeyWrapAlgorithmTest.class);

    public void testRoundTrip() throws JoseException
    {
        AlgorithmFactoryFactory aff = AlgorithmFactoryFactory.getInstance();
        AlgorithmFactory<ContentEncryptionAlgorithm> encAlgFactory = aff.getJweContentEncryptionAlgorithmFactory();
        AlgorithmFactory<KeyManagementAlgorithm> algAlgFactory = aff.getJweKeyManagementAlgorithmFactory();
        Set<String> supportedAlgAlgorithms = algAlgFactory.getSupportedAlgorithms();
        Set<String> supportedEncAlgorithms = encAlgFactory.getSupportedAlgorithms();


        String[] algArray = {KeyManagementAlgorithmIdentifiers.ECDH_ES_A128KW,
                         KeyManagementAlgorithmIdentifiers.ECDH_ES_A192KW,
                         KeyManagementAlgorithmIdentifiers.ECDH_ES_A256KW};

        Set<String> algs = new HashSet<>(Arrays.asList(algArray));
        boolean algsReduced = algs.retainAll(supportedAlgAlgorithms);

        String[] encArray = {ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256,
                         ContentEncryptionAlgorithmIdentifiers.AES_192_CBC_HMAC_SHA_384,
                         ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512};

        Set<String> encs = new HashSet<>(Arrays.asList(encArray));
        boolean encsReduced = encs.retainAll(supportedEncAlgorithms);

        if (algsReduced || encsReduced)
        {
            log.warn("*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*");
            log.warn("It looks like the JCE's Unlimited Strength Jurisdiction Policy Files are not installed for the JRE.");
            log.warn("So some algorithms are not available and will not be tested.");
            log.warn("{} vs {}", algs, Arrays.toString(algArray));
            log.warn("{} vs {}", encs, Arrays.toString(encArray));
            log.warn("*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*");
        }

        for (String alg : algs)
        {
            for (String enc : encs)
            {
                jweRoundTrip(alg, enc);
            }
        }

    }

    private void jweRoundTrip(String alg, String enc) throws JoseException
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

        log.debug("JWE w/ {} & {}: {}", alg, enc, compactSerialization);

        JsonWebEncryption receiverJwe = new JsonWebEncryption();
        receiverJwe.setCompactSerialization(compactSerialization);
        receiverJwe.setKey(receiverJwk.getPrivateKey());

        assertEquals(plaintext, receiverJwe.getPlaintextString());
    }
}
