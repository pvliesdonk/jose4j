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
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.lang.ByteGenerator;
import org.jose4j.lang.DefaultByteGenerator;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.StringUtil;

/**
 */
public class JsonWebEncryption extends JsonWebStructure
{
    private Base64Url base64url = new Base64Url();
    
    private String plaintextCharEncoding = StringUtil.UTF_8;
    private byte[] plaintext;

    private ByteGenerator byteGenerator = new DefaultByteGenerator();

    public void setByteGenerator(ByteGenerator byteGenerator)
    {
        this.byteGenerator = byteGenerator;
    }

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


    private ContentEncryptionAlgorithm getEncryptionMethodAlgorithm() throws JoseException
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

        return "todo.getthis.working.ok";
    }

}
