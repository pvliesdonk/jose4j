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
package org.jose4j.jca;

import org.hamcrest.CoreMatchers;
import org.jose4j.jwa.JceProviderTestSupport;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.keys.AesKey;
import org.jose4j.keys.ExampleEcKeysFromJws;
import org.jose4j.keys.ExampleRsaJwksFromJwe;
import org.jose4j.keys.HmacKey;
import org.jose4j.lang.JoseException;
import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;

/**
 *
 */
public class ProviderContextTest
{
    public static final String NO_SUCH_PROVIDER = "-_NO__SUCH__PROVIDER_-";

    public static final ProviderContext EMPTY_CONTEXT = new ProviderContext();

    @Test
    public void testGeneralDefaulting()
    {
        ProviderContext pc = new ProviderContext();
        Assert.assertNull(pc.getSecureRandom());

        String generalProvider = "some-provider";
        String specificProvider = "some-other-provider";

        for (ProviderContext.Context pcc : new ProviderContext.Context[] {pc.getGeneralProviderContext(), pc.getSuppliedKeyProviderContext()})
        {
            Assert.assertNull(pcc.getGeneralProvider());

            Assert.assertNull(pcc.getCipherProvider());
            Assert.assertNull(pcc.getKeyAgreementProvider());
            Assert.assertNull(pcc.getKeyFactoryProvider());
            Assert.assertNull(pcc.getKeyPairGeneratorProvider());
            Assert.assertNull(pcc.getMacProvider());
            Assert.assertNull(pcc.getMessageDigestProvider());
            Assert.assertNull(pcc.getSignatureProvider());

            pcc.setGeneralProvider(generalProvider);
            Assert.assertThat(pcc.getCipherProvider(), CoreMatchers.equalTo(generalProvider));
            pcc.setCipherProvider(specificProvider);
            Assert.assertThat(pcc.getCipherProvider(), CoreMatchers.equalTo(specificProvider));

            pcc.setGeneralProvider(generalProvider);
            Assert.assertThat(pcc.getKeyAgreementProvider(), CoreMatchers.equalTo(generalProvider));
            pcc.setKeyAgreementProvider(specificProvider);
            Assert.assertThat(pcc.getKeyAgreementProvider(), CoreMatchers.equalTo(specificProvider));

            pcc.setGeneralProvider(generalProvider);
            Assert.assertThat(pcc.getKeyFactoryProvider(), CoreMatchers.equalTo(generalProvider));
            pcc.setKeyFactoryProvider(specificProvider);
            Assert.assertThat(pcc.getKeyFactoryProvider(), CoreMatchers.equalTo(specificProvider));

            pcc.setGeneralProvider(generalProvider);
            Assert.assertThat(pcc.getKeyPairGeneratorProvider(), CoreMatchers.equalTo(generalProvider));
            pcc.setKeyPairGeneratorProvider(specificProvider);
            Assert.assertThat(pcc.getKeyPairGeneratorProvider(), CoreMatchers.equalTo(specificProvider));

            pcc.setGeneralProvider(generalProvider);
            Assert.assertThat(pcc.getMacProvider(), CoreMatchers.equalTo(generalProvider));
            pcc.setMacProvider(specificProvider);
            Assert.assertThat(pcc.getMacProvider(), CoreMatchers.equalTo(specificProvider));

            pcc.setGeneralProvider(generalProvider);
            Assert.assertThat(pcc.getMessageDigestProvider(), CoreMatchers.equalTo(generalProvider));
            pcc.setMessageDigestProvider(specificProvider);
            Assert.assertThat(pcc.getMessageDigestProvider(), CoreMatchers.equalTo(specificProvider));

            pcc.setGeneralProvider(generalProvider);
            Assert.assertThat(pcc.getSignatureProvider(), CoreMatchers.equalTo(generalProvider));
            pcc.setSignatureProvider(specificProvider);
            Assert.assertThat(pcc.getSignatureProvider(), CoreMatchers.equalTo(specificProvider));
        }
    }

    @Test
    public void kindaLameTestForNonexistentProviderJwsRsa() throws JoseException
    {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload("meh");
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setKey(ExampleRsaJwksFromJwe.APPENDIX_A_1.getPrivateKey());
        ProviderContext providerCtx = new ProviderContext();
        providerCtx.getSuppliedKeyProviderContext().setSignatureProvider(NO_SUCH_PROVIDER);
        jws.setProviderContext(providerCtx);
        expectNoProviderProduce(jws);

        jws.setProviderContext(EMPTY_CONTEXT);
        String jwsCompactSerialization = jws.getCompactSerialization();

        jws = new JsonWebSignature();
        jws.setCompactSerialization(jwsCompactSerialization);
        jws.setKey(ExampleRsaJwksFromJwe.APPENDIX_A_1.getPublicKey());
        jws.setProviderContext(providerCtx);
        expectNoProviderConsume(jws);

        jws.setProviderContext(EMPTY_CONTEXT);
        Assert.assertTrue(jws.verifySignature());
    }


    @Test
    public void kindaLameTestForNonexistentProviderJwsEc() throws JoseException
    {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload("whatever");
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        jws.setKey(ExampleEcKeysFromJws.PRIVATE_256);
        ProviderContext providerCtx = new ProviderContext();
        providerCtx.getSuppliedKeyProviderContext().setSignatureProvider(NO_SUCH_PROVIDER);
        jws.setProviderContext(providerCtx);
        expectNoProviderProduce(jws);

        jws.setProviderContext(EMPTY_CONTEXT);
        String jwsCompactSerialization = jws.getCompactSerialization();

        jws = new JsonWebSignature();
        jws.setCompactSerialization(jwsCompactSerialization);
        jws.setKey(ExampleEcKeysFromJws.PUBLIC_256);
        jws.setProviderContext(providerCtx);
        expectNoProviderConsume(jws);

        jws.setProviderContext(EMPTY_CONTEXT);
        Assert.assertTrue(jws.verifySignature());
    }

    @Test
    public void kindaLameTestForNonexistentProviderJwsHmac() throws JoseException
    {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload("okay");
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
        HmacKey key = new HmacKey(new byte[32]);
        jws.setKey(key);
        ProviderContext providerCtx = new ProviderContext();
        providerCtx.getSuppliedKeyProviderContext().setMacProvider(NO_SUCH_PROVIDER);
        jws.setProviderContext(providerCtx);
        expectNoProviderProduce(jws);

        jws.setProviderContext(EMPTY_CONTEXT);
        String jwsCompactSerialization = jws.getCompactSerialization();

        jws = new JsonWebSignature();
        jws.setCompactSerialization(jwsCompactSerialization);
        jws.setKey(key);
        jws.setProviderContext(providerCtx);
        expectNoProviderConsume(jws);

        jws.setProviderContext(EMPTY_CONTEXT);
        Assert.assertTrue(jws.verifySignature());
    }

    void expectNoProviderProduce(JsonWebStructure jwx)
    {
        try
        {
            String compactSerialization = jwx.getCompactSerialization();
            Assert.fail("Shouldn't have gotten compact serialization " + compactSerialization);
        }
        catch (JoseException e)
        {
            Assert.assertThat(e.getMessage(), CoreMatchers.containsString(NO_SUCH_PROVIDER));
        }
    }

    void expectNoProviderConsume(JsonWebStructure jwx)
    {
        try
        {
            String inside = jwx.getPayload();
            Assert.fail("Shouldn't have gotten payload " + inside);
        }
        catch (JoseException e)
        {
            Assert.assertThat(e.getMessage(), CoreMatchers.containsString(NO_SUCH_PROVIDER));
        }
    }

    @Test
    public void kindaLameTestForNonexistentProviderJweRsaOaepAnd15() throws JoseException
    {
        for (String alg : new String[] {KeyManagementAlgorithmIdentifiers.RSA_OAEP, KeyManagementAlgorithmIdentifiers.RSA1_5})
        {
            JsonWebEncryption jwe = new JsonWebEncryption();
            String payload = "meh";
            jwe.setPayload(payload);
            jwe.setAlgorithmHeaderValue(alg);
            jwe.setKey(ExampleRsaJwksFromJwe.APPENDIX_A_1.getPublicKey());
            jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
            ProviderContext providerCtx = new ProviderContext();
            providerCtx.getSuppliedKeyProviderContext().setCipherProvider(NO_SUCH_PROVIDER);
            jwe.setProviderContext(providerCtx);
            expectNoProviderProduce(jwe);

            jwe.setProviderContext(EMPTY_CONTEXT);
            String jwsCompactSerialization = jwe.getCompactSerialization();

            jwe = new JsonWebEncryption();
            jwe.setCompactSerialization(jwsCompactSerialization);
            jwe.setKey(ExampleRsaJwksFromJwe.APPENDIX_A_1.getPrivateKey());
            jwe.setProviderContext(providerCtx);
            expectNoProviderConsume(jwe);

            jwe.setProviderContext(EMPTY_CONTEXT);
            Assert.assertThat(jwe.getPayload(), CoreMatchers.equalTo(payload));
        }
    }

    @Test
    public void kindaLameTestForNonexistentProviderJweDirAesMac() throws JoseException
    {
        final String mac = "MAC";
        final String cipher = "Cipher";
        for (String which : new String[] {mac, cipher})
        {
            JsonWebEncryption jwe = new JsonWebEncryption();
            String payload = "meh";
            jwe.setPayload(payload);
            jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.DIRECT);
            AesKey key = new AesKey(new byte[32]);
            jwe.setKey(key);
            jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
            ProviderContext providerCtx = new ProviderContext();
            switch (which)
            {
                case cipher:
                    providerCtx.getSuppliedKeyProviderContext().setCipherProvider(NO_SUCH_PROVIDER);
                    break;
                case mac:
                    providerCtx.getSuppliedKeyProviderContext().setMacProvider(NO_SUCH_PROVIDER);
                    break;
                default:
                    Assert.fail("shouldn't get here");
            }
            jwe.setProviderContext(providerCtx);
            expectNoProviderProduce(jwe);

            jwe = new JsonWebEncryption();
            jwe.setPayload(payload);
            jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.DIRECT);
            jwe.setKey(key);
            jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
            jwe.setProviderContext(EMPTY_CONTEXT);
            String jwsCompactSerialization = jwe.getCompactSerialization();

            jwe = new JsonWebEncryption();
            jwe.setCompactSerialization(jwsCompactSerialization);
            jwe.setKey(key);
            jwe.setProviderContext(providerCtx);
            expectNoProviderConsume(jwe);

            jwe.setProviderContext(EMPTY_CONTEXT);
            Assert.assertThat(jwe.getPayload(), CoreMatchers.equalTo(payload));
        }
    }

    @Test
    public void kindaLameTestForNonexistentProviderJweAesCbcHmac() throws JoseException
    {
        JsonWebEncryption jwe = new JsonWebEncryption();
        String payload = "meh";
        jwe.setPayload(payload);
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.DIRECT);
        AesKey key = new AesKey(new byte[32]);
        jwe.setKey(key);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        ProviderContext providerCtx = new ProviderContext();
        providerCtx.getSuppliedKeyProviderContext().setCipherProvider(NO_SUCH_PROVIDER);
        jwe.setProviderContext(providerCtx);
        expectNoProviderProduce(jwe);

        jwe = new JsonWebEncryption();
        jwe.setPayload(payload);
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.DIRECT);
        jwe.setKey(key);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        jwe.setProviderContext(EMPTY_CONTEXT);
        String jwsCompactSerialization = jwe.getCompactSerialization();

        jwe = new JsonWebEncryption();
        jwe.setCompactSerialization(jwsCompactSerialization);
        jwe.setKey(key);
        jwe.setProviderContext(providerCtx);
        expectNoProviderConsume(jwe);

        jwe.setProviderContext(EMPTY_CONTEXT);
        Assert.assertThat(jwe.getPayload(), CoreMatchers.equalTo(payload));
    }

    @Test
    public void kindaLameTestForNonexistentProviderJweAeskws() throws Exception
    {
        JceProviderTestSupport support = new JceProviderTestSupport();
        support.setKeyManagementAlgsNeeded(KeyManagementAlgorithmIdentifiers.A128GCMKW);
        support.runWithBouncyCastleProviderIfNeeded(new JceProviderTestSupport.RunnableTest()
        {
            @Override
            public void runTest() throws Exception
            {
                for (String alg : new String[] {KeyManagementAlgorithmIdentifiers.A128KW, KeyManagementAlgorithmIdentifiers.A128GCMKW})
                {
                    JsonWebEncryption jwe = new JsonWebEncryption();
                    String payload = "meh";
                    jwe.setPayload(payload);
                    jwe.setAlgorithmHeaderValue(alg);
                    AesKey key = new AesKey(new byte[16]);
                    jwe.setKey(key);
                    jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_GCM);
                    ProviderContext providerCtx = new ProviderContext();
                    providerCtx.getSuppliedKeyProviderContext().setCipherProvider(NO_SUCH_PROVIDER);
                    jwe.setProviderContext(providerCtx);
                    expectNoProviderProduce(jwe);

                    jwe.setProviderContext(EMPTY_CONTEXT);
                    String jwsCompactSerialization = jwe.getCompactSerialization();

                    jwe = new JsonWebEncryption();
                    jwe.setCompactSerialization(jwsCompactSerialization);
                    jwe.setKey(key);
                    jwe.setProviderContext(providerCtx);
                    expectNoProviderConsume(jwe);

                    jwe.setProviderContext(EMPTY_CONTEXT);
                    Assert.assertThat(jwe.getPayload(), CoreMatchers.equalTo(payload));
                }
            }
        });
    }

    @Test
    public void kindaLameTestForNonexistentProviderJweEc() throws JoseException
    {
        String[] algs = {KeyManagementAlgorithmIdentifiers.ECDH_ES,
                KeyManagementAlgorithmIdentifiers.ECDH_ES_A128KW,
                KeyManagementAlgorithmIdentifiers.ECDH_ES_A256KW,
                KeyManagementAlgorithmIdentifiers.ECDH_ES_A192KW};
        final String keyFactory = "KF";
        final String keyAgreement = "KA";
        final String keyPairGenerator = "KPG";
        for (String whichKind : new String []{keyFactory, keyAgreement, keyPairGenerator})
        {
            for (String alg : algs)
            {
                JsonWebEncryption jwe = new JsonWebEncryption();
                String payload = "meh";
                jwe.setPayload(payload);
                jwe.setAlgorithmHeaderValue(alg);
                jwe.setKey(ExampleEcKeysFromJws.PUBLIC_256);
                jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
                ProviderContext providerCtx = new ProviderContext();
                switch (whichKind)
                {
                    case keyAgreement:
                        providerCtx.getSuppliedKeyProviderContext().setKeyAgreementProvider(NO_SUCH_PROVIDER);
                        break;
                    case keyFactory:
                        providerCtx.getGeneralProviderContext().setKeyFactoryProvider(NO_SUCH_PROVIDER);
                        break;
                    case keyPairGenerator:
                        providerCtx.getGeneralProviderContext().setKeyPairGeneratorProvider(NO_SUCH_PROVIDER);
                        break;
                     default:
                         Assert.fail("shouldn't get here");
                }

                jwe.setProviderContext(providerCtx);
                if (!whichKind.equals(keyFactory)) // keyfactory is only used on consuming
                {
                    expectNoProviderProduce(jwe);
                }

                jwe.setProviderContext(EMPTY_CONTEXT);
                String jwsCompactSerialization = jwe.getCompactSerialization();

                jwe = new JsonWebEncryption();
                jwe.setCompactSerialization(jwsCompactSerialization);
                jwe.setKey(ExampleEcKeysFromJws.PRIVATE_256);
                jwe.setProviderContext(providerCtx);
                if (!whichKind.equals(keyPairGenerator))
                {
                    expectNoProviderConsume(jwe);
                }

                jwe.setProviderContext(EMPTY_CONTEXT);
                Assert.assertThat(jwe.getPayload(), CoreMatchers.equalTo(payload));
            }
        }
    }

    @Test
    public void kindaLameTestForSelectingProviderJwsRsaWithBC() throws Exception
    {
        JceProviderTestSupport support = new JceProviderTestSupport();
        support.setUseBouncyCastleRegardlessOfAlgs(true);
        support.setPutBouncyCastleFirst(false);
        support.runWithBouncyCastleProviderIfNeeded(new JceProviderTestSupport.RunnableTest()
        {
            @Override
            public void runTest() throws Exception
            {
                JsonWebSignature jws = new JsonWebSignature();
                jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
                jws.setPayload("sign this");

                RSAPrivateKey pk = new RSAPrivateKey()
                {
                    RSAPrivateKey delegateKey = (RSAPrivateKey) ExampleRsaJwksFromJwe.APPENDIX_A_1.getPrivateKey();

                    @Override
                    public String getAlgorithm()
                    {
                        return delegateKey.getAlgorithm();
                    }

                    @Override
                    public String getFormat()
                    {
                        return delegateKey.getFormat();
                    }

                    @Override
                    public byte[] getEncoded()
                    {
                        return delegateKey.getEncoded();
                    }

                    @Override
                    public BigInteger getPrivateExponent()
                    {
                        lookAtStackTraceForBC();
                        return delegateKey.getPrivateExponent();
                    }

                    @Override
                    public BigInteger getModulus()
                    {
                        return delegateKey.getModulus();
                    }

                    private void lookAtStackTraceForBC()
                    {
                        boolean bc = false;
                        for (StackTraceElement ste : new Exception().getStackTrace())
                        {
                            if (ste.getClassName().contains(".bouncycastle."))
                            {
                                bc = true;
                            }
                        }

                        if (!bc)
                        {
                            throw new IllegalStateException("Bouncy Castle not used!");
                        }
                    }
                };

                jws.setKey(pk);
                ProviderContext pc = new ProviderContext();
                pc.getSuppliedKeyProviderContext().setSignatureProvider("BC");
                jws.setProviderContext(pc);
                jws.getCompactSerialization();
            }
        });
    }

    @Test
    public void kindaLameTestForSelectingProviderForContentEncGcm() throws Exception
    {
        JceProviderTestSupport support = new JceProviderTestSupport();
        support.setUseBouncyCastleRegardlessOfAlgs(true);
        support.setPutBouncyCastleFirst(false);
        support.runWithBouncyCastleProviderIfNeeded(new JceProviderTestSupport.RunnableTest()
        {
            @Override
            public void runTest() throws Exception
            {

                for (String enc : new String[] {ContentEncryptionAlgorithmIdentifiers.AES_128_GCM, ContentEncryptionAlgorithmIdentifiers.AES_128_GCM, ContentEncryptionAlgorithmIdentifiers.AES_256_GCM})
                {
                    JsonWebEncryption jwe = new JsonWebEncryption();
                    jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.A128KW);
                    jwe.setEncryptionMethodHeaderParameter(enc);
                    final String payloadIn = "encrypt me";
                    jwe.setPayload(payloadIn);

                    final AesKey key = new AesKey(new byte[]{1, 2, 1, 1, 0, 0, 1, 2, 9, 1, 0, 5, 1, 7, 1, 4});
                    jwe.setKey(key);
                    ProviderContext pc = new ProviderContext();
                    pc.getGeneralProviderContext().setCipherProvider(NO_SUCH_PROVIDER);
                    jwe.setProviderContext(pc);
                    expectNoProviderProduce(jwe);

                    jwe = new JsonWebEncryption();
                    jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.A128KW);
                    jwe.setEncryptionMethodHeaderParameter(enc);
                    jwe.setPayload(payloadIn);
                    jwe.setKey(key);
                    final String compactSerialization = jwe.getCompactSerialization();

                    jwe = new JsonWebEncryption();
                    jwe.setCompactSerialization(compactSerialization);
                    jwe.setKey(key);
                    Assert.assertThat(jwe.getPayload(), CoreMatchers.equalTo(payloadIn));

                    jwe = new JsonWebEncryption();
                    jwe.setCompactSerialization(compactSerialization);
                    jwe.setKey(key);
                    jwe.setProviderContext(pc);
                    expectNoProviderConsume(jwe);
                }
            }
        });
    }

    @Test
    public void kindaLameTestForSelectingProviderForContentEncCbcHmac() throws Exception
    {
        for (boolean doMac : new boolean[] {true, false})
        {
            for (String enc : new String[] {ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256, ContentEncryptionAlgorithmIdentifiers.AES_192_CBC_HMAC_SHA_384, ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512})
            {
                JsonWebEncryption jwe = new JsonWebEncryption();
                jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.A128KW);
                jwe.setEncryptionMethodHeaderParameter(enc);
                final String payloadIn = "encrypt me";
                jwe.setPayload(payloadIn);

                final AesKey key = new AesKey(new byte[]{1, 2, 1, 1, 0, 0, 1, 2, 9, 1, 0, 5, 1, 7, 1, 4});
                jwe.setKey(key);
                ProviderContext pc = new ProviderContext();
                final ProviderContext.Context providerContext = pc.getGeneralProviderContext();
                if (doMac)
                {
                    providerContext.setMacProvider(NO_SUCH_PROVIDER);
                }
                else
                {
                    providerContext.setCipherProvider(NO_SUCH_PROVIDER);
                }

                jwe.setProviderContext(pc);
                expectNoProviderProduce(jwe);

                jwe = new JsonWebEncryption();
                jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.A128KW);
                jwe.setEncryptionMethodHeaderParameter(enc);
                jwe.setPayload(payloadIn);
                jwe.setKey(key);
                final String compactSerialization = jwe.getCompactSerialization();

                jwe = new JsonWebEncryption();
                jwe.setCompactSerialization(compactSerialization);
                jwe.setKey(key);
                Assert.assertThat(jwe.getPayload(), CoreMatchers.equalTo(payloadIn));

                jwe = new JsonWebEncryption();
                jwe.setCompactSerialization(compactSerialization);
                jwe.setKey(key);
                jwe.setProviderContext(pc);
                expectNoProviderConsume(jwe);
            }
        }
    }

}
