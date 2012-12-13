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

package org.jose4j.jws;

import org.jose4j.keys.RsaKeyUtil;
import org.jose4j.lang.JoseException;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

/**
 */
public class RsaUsingShaAlgorithm extends BaseSignatureAlgorithm implements JsonWebSignatureAlgorithm
{
    static final int MIN_RSA_KEY_LENGTH = 2048;    

    public RsaUsingShaAlgorithm(String id, String javaAlgo)
    {
        super(id, javaAlgo, RsaKeyUtil.RSA);
    }

    public void validatePublicKey(PublicKey key) throws JoseException
    {
        int size = ((RSAPublicKey) key).getModulus().bitLength();
        if  (size < MIN_RSA_KEY_LENGTH)
        {
            throw new JoseException("A key of size "+MIN_RSA_KEY_LENGTH+
                    " bits or larger MUST be used with the RSA digital signature algorithms (given key was only "+size+ " bits).");
        }
    }

    public void validatePrivateKey(PrivateKey privateKey) throws JoseException
    {
        // todo
    }
}
