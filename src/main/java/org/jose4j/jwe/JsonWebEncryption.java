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

package org.jose4j.jwe;

import org.jose4j.base64url.Base64Url;
import org.jose4j.jwa.AlgorithmFactoryFactory;
import org.jose4j.jwx.CompactSerialization;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.StringUtil;

import java.security.Key;

/**
 */
public class JsonWebEncryption extends JsonWebStructure
{
    private Base64Url base64url = new Base64Url();
    
    private String plaintextCharEncoding = StringUtil.UTF_8;
    private byte[] plaintext;

    public void setPlainTextCharEncoding(String plaintextCharEncoding)
    {
        this.plaintextCharEncoding = plaintextCharEncoding;
    }

    public void setPlaintext(byte[] plaintext)
    {
        this.plaintext = plaintext;
    }

    public void setPlaintext(String plaintext)
    {
        this.plaintext = StringUtil.getBytesUnchecked(plaintext, plaintextCharEncoding);
    }

    public String getPlaintextString()
    {
        return StringUtil.newString(plaintext, plaintextCharEncoding);
    }

    public byte[] getPlaintextBytes()
    {
        return plaintext;
    }

    private ContentEncryptionAlgorithm getContentEncryptionAlgorithm() throws JoseException
    {
        String algo = getHeader(HeaderParameterNames.ENCRYPTION_METHOD);
        if (algo == null)
        {
            throw new JoseException(HeaderParameterNames.ENCRYPTION_METHOD + " header not set.");
        }
        AlgorithmFactoryFactory factoryFactory = AlgorithmFactoryFactory.getInstance();
        return factoryFactory.getSymmetricEncryptionAlgorithm(algo);
    }

    private KeyManagementModeAlgorithm getKeyManagementModeAlgorithm() throws JoseException
    {
        String algo = getAlgorithmHeaderValue();
        if (algo == null)
        {
            throw new JoseException(HeaderParameterNames.ALGORITHM + " header not set.");
        }
        AlgorithmFactoryFactory factoryFactory = AlgorithmFactoryFactory.getInstance();
        return factoryFactory.getKeyManagementModeAlgorithm(algo);
    }


    public String getCompactSerialization() throws JoseException
    {
        KeyManagementModeAlgorithm keyManagementModeAlg = getKeyManagementModeAlgorithm();
        ContentEncryptionAlgorithm contentEncryptionAlg = getContentEncryptionAlgorithm();

        ContentEncryptionKeyDescriptor contentEncryptionKeyDesc = contentEncryptionAlg.getContentEncryptionKeyDescriptor();
        Key managementKey = getKey();
        ContentEncryptionKeys contentEncryptionKeys = keyManagementModeAlg.manageForEncrypt(managementKey, contentEncryptionKeyDesc);

        String encodedHeader = getEncodedHeader();
        byte[] aad = StringUtil.getBytesAscii(encodedHeader);
        byte[] contentEncryptionKey = contentEncryptionKeys.getContentEncryptionKey();
        ContentEncryptionParts contentEncryptionParts = contentEncryptionAlg.encrypt(getPlaintextBytes(), aad, contentEncryptionKey);

        String encodedIv = base64url.base64UrlEncode(contentEncryptionParts.getIv());
        String encodedCiphertext = base64url.base64UrlEncode(contentEncryptionParts.getCiphertext());
        String encodedTag = base64url.base64UrlEncode(contentEncryptionParts.getAuthenticationTag());

        byte[] encryptedKey = contentEncryptionKeys.getEncryptedKey();
        String encodedEncryptedKey = base64url.base64UrlEncode(encryptedKey);

        return CompactSerialization.serialize(encodedHeader, encodedEncryptedKey, encodedIv, encodedCiphertext, encodedTag);
    }


}
