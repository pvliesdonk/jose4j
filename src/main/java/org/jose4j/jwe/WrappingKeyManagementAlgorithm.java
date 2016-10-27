/*
 * Copyright 2012-2016 Brian Campbell
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

import org.jose4j.jca.ProviderContext;
import org.jose4j.jwa.AlgorithmInfo;
import org.jose4j.jwx.Headers;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.ExceptionHelp;
import org.jose4j.lang.JoseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

/**
 */
public abstract class WrappingKeyManagementAlgorithm extends AlgorithmInfo implements KeyManagementAlgorithm
{
    protected final Logger log = LoggerFactory.getLogger(getClass());

    private AlgorithmParameterSpec algorithmParameterSpec;
    protected boolean useSuppliedKeyProviderContext = true;

    public WrappingKeyManagementAlgorithm(String javaAlg, String alg)
    {
        setJavaAlgorithm(javaAlg);
        setAlgorithmIdentifier(alg);
    }

    public void setAlgorithmParameterSpec(AlgorithmParameterSpec algorithmParameterSpec)
    {
        this.algorithmParameterSpec = algorithmParameterSpec;
    }

    public ContentEncryptionKeys manageForEncrypt(Key managementKey, ContentEncryptionKeyDescriptor cekDesc, Headers headers, byte[] cekOverride, ProviderContext providerContext) throws JoseException
    {
        byte[] contentEncryptionKey = cekOverride == null ? ByteUtil.randomBytes(cekDesc.getContentEncryptionKeyByteLength()) : cekOverride;
        return manageForEnc(managementKey, cekDesc, contentEncryptionKey, providerContext);
    }

    protected ContentEncryptionKeys manageForEnc(Key managementKey, ContentEncryptionKeyDescriptor cekDesc, byte[] contentEncryptionKey, ProviderContext providerContext) throws JoseException
    {
        ProviderContext.Context ctx = useSuppliedKeyProviderContext ? providerContext.getSuppliedKeyProviderContext() : providerContext.getGeneralProviderContext();
        String provider = ctx.getCipherProvider();

        Cipher cipher = CipherUtil.getCipher(getJavaAlgorithm(), provider);

        try
        {
            initCipher(cipher, Cipher.WRAP_MODE, managementKey);
            String contentEncryptionKeyAlgorithm = cekDesc.getContentEncryptionKeyAlgorithm();
            byte[] encryptedKey = cipher.wrap(new SecretKeySpec(contentEncryptionKey, contentEncryptionKeyAlgorithm));
            return new ContentEncryptionKeys(contentEncryptionKey, encryptedKey);
        }
        catch  (InvalidKeyException e)
        {
            throw new org.jose4j.lang.InvalidKeyException("Unable to encrypt ("+cipher.getAlgorithm()+") the Content Encryption Key: " + e, e);
        }
        catch (IllegalBlockSizeException | InvalidAlgorithmParameterException e)
        {
            throw new JoseException("Unable to encrypt ("+cipher.getAlgorithm()+") the Content Encryption Key: " + e, e);
        }
    }

    void initCipher(Cipher cipher, int mode, Key key) throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        if (algorithmParameterSpec == null)
        {
            cipher.init(mode, key);
        }
        else
        {
            cipher.init(mode, key, algorithmParameterSpec);
        }
    }

    public Key manageForDecrypt(Key managementKey, byte[] encryptedKey, ContentEncryptionKeyDescriptor cekDesc, Headers headers, ProviderContext providerContext) throws JoseException
    {
        String provider = providerContext.getSuppliedKeyProviderContext().getCipherProvider();
        Cipher cipher = CipherUtil.getCipher(getJavaAlgorithm(), provider);

        try
        {
            initCipher(cipher, Cipher.UNWRAP_MODE, managementKey);
        }
        catch  (InvalidKeyException e)
        {
            throw new org.jose4j.lang.InvalidKeyException("Unable to initialize cipher ("+cipher.getAlgorithm()+") for key decryption", e);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new JoseException("Unable to initialize cipher ("+cipher.getAlgorithm()+") for key decryption", e);
        }

        String cekAlg = cekDesc.getContentEncryptionKeyAlgorithm();

        try
        {
            return cipher.unwrap(encryptedKey, cekAlg, Cipher.SECRET_KEY);
        }
        catch (Exception e)
        {
            if (log.isDebugEnabled())
            {
                String flatStack = ExceptionHelp.toStringWithCausesAndAbbreviatedStack(e, JsonWebEncryption.class);
                log.debug("Key unwrap failed. Substituting a randomly generated CEK and proceeding. {}", flatStack);
            }
            /* https://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-39#section-11.5
                   and doing this should also result in the same type of error for different types of problems as suggested 11.4

               To mitigate the attacks described in RFC 3218 [RFC3218], the
               recipient MUST NOT distinguish between format, padding, and length
               errors of encrypted keys.  It is strongly recommended, in the event
               of receiving an improperly formatted key, that the recipient
               substitute a randomly generated CEK and proceed to the next step, to
               mitigate timing attacks.
             */
            byte[] bytes = ByteUtil.randomBytes(cekDesc.getContentEncryptionKeyByteLength());
            return new SecretKeySpec(bytes, cekAlg);
        }
    }
}
