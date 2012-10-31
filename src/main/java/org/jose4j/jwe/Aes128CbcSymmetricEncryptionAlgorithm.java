/*
 * Copyright 2012 Brian Campbell
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

import org.jose4j.jwa.AlgorithmInfo;
import org.jose4j.lang.JoseException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;

/**
 */
public class Aes128CbcSymmetricEncryptionAlgorithm extends AlgorithmInfo implements SymmetricEncryptionAlgorithm
{
    public Aes128CbcSymmetricEncryptionAlgorithm()
    {
        setAlgorithmIdentifier(SymmetricEncryptionAlgorithmIdentifiers.A128CBC);
        setJavaAlgorithm("AES/CBC/PKCS5Padding");
    }

    public int getKeySize()
    {
        return 128;
    }

    public boolean isAead()
    {
        return false;
    }

    public Result encrypt(byte[] plaintext, byte[] key)
    {
        return null;
//        Cipher cipher = getCipher();
//        SecretKeySpec spec = new SecretKeySpec(key, "AES");
//        ??? or make key elsewhere?
//        cipher.init(Cipher.ENCRYPT_MODE, );

    }

    private Cipher getCipher() throws JoseException
    {
        try
        {
            return Cipher.getInstance(getJavaAlgorithm());
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new JoseException(e.toString() , e);
        }
        catch (NoSuchPaddingException e)
        {
            throw new JoseException(e.toString() , e);
        }
    }
}
