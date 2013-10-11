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

import junit.framework.TestCase;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.keys.AesKey;
import org.jose4j.keys.ExampleEcKeysFromJws;
import org.jose4j.keys.ExampleRsaJwksFromJwe;
import org.jose4j.lang.JoseException;

import java.security.Key;

import static org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers.*;
import static org.jose4j.jwe.KeyManagementAlgorithmIdentifiers.*;

/**
 */
public class NegativeJweKeyTest extends TestCase
{
    Log log = LogFactory.getLog(this.getClass());

    public void testA128KW() throws JoseException
    {
        expectBadKeyFail(A128KW, AES_128_CBC_HMAC_SHA_256, aesKey(1));
        expectBadKeyFail(A128KW, AES_128_CBC_HMAC_SHA_256, aesKey(5));
        expectBadKeyFail(A128KW, AES_128_CBC_HMAC_SHA_256, aesKey(17));
        expectBadKeyFail(A128KW, AES_128_CBC_HMAC_SHA_256, aesKey(24));
        expectBadKeyFail(A128KW, AES_128_CBC_HMAC_SHA_256, aesKey(32));
        expectBadKeyFail(A128KW, AES_128_CBC_HMAC_SHA_256, ExampleRsaJwksFromJwe.APPENDIX_A_1.getPrivateKey());
        expectBadKeyFail(A128KW, AES_128_CBC_HMAC_SHA_256, ExampleRsaJwksFromJwe.APPENDIX_A_1.getPublicKey());
        expectBadKeyFail(A128KW, AES_128_CBC_HMAC_SHA_256, ExampleEcKeysFromJws.PRIVATE_256);
        expectBadKeyFail(A128KW, AES_128_CBC_HMAC_SHA_256, ExampleEcKeysFromJws.PUBLIC_256);
    }

    public void testA192KW() throws JoseException
    {
        expectBadKeyFail(A192KW, AES_192_CBC_HMAC_SHA_384, aesKey(1));
        expectBadKeyFail(A192KW, AES_192_CBC_HMAC_SHA_384, aesKey(5));
        expectBadKeyFail(A192KW, AES_192_CBC_HMAC_SHA_384, aesKey(16));
        expectBadKeyFail(A192KW, AES_192_CBC_HMAC_SHA_384, aesKey(23));
        expectBadKeyFail(A192KW, AES_192_CBC_HMAC_SHA_384, aesKey(32));
        expectBadKeyFail(A192KW, AES_192_CBC_HMAC_SHA_384, ExampleRsaJwksFromJwe.APPENDIX_A_1.getPrivateKey());
        expectBadKeyFail(A192KW, AES_192_CBC_HMAC_SHA_384, ExampleRsaJwksFromJwe.APPENDIX_A_1.getPublicKey());
        expectBadKeyFail(A192KW, AES_192_CBC_HMAC_SHA_384, ExampleEcKeysFromJws.PRIVATE_256);
        expectBadKeyFail(A192KW, AES_192_CBC_HMAC_SHA_384, ExampleEcKeysFromJws.PUBLIC_256);
    }

    public void testA256KW() throws JoseException
    {
        expectBadKeyFail(A256KW, AES_256_CBC_HMAC_SHA_512, aesKey(1));
        expectBadKeyFail(A256KW, AES_256_CBC_HMAC_SHA_512, aesKey(5));
        expectBadKeyFail(A256KW, AES_256_CBC_HMAC_SHA_512, aesKey(16));
        expectBadKeyFail(A256KW, AES_256_CBC_HMAC_SHA_512, aesKey(24));
        expectBadKeyFail(A256KW, AES_256_CBC_HMAC_SHA_512, aesKey(31));
        expectBadKeyFail(A256KW, AES_256_CBC_HMAC_SHA_512, aesKey(33));
        expectBadKeyFail(A256KW, AES_256_CBC_HMAC_SHA_512, ExampleRsaJwksFromJwe.APPENDIX_A_2.getPrivateKey());
        expectBadKeyFail(A256KW, AES_256_CBC_HMAC_SHA_512, ExampleRsaJwksFromJwe.APPENDIX_A_2.getPublicKey());
        expectBadKeyFail(A256KW, AES_256_CBC_HMAC_SHA_512, ExampleEcKeysFromJws.PRIVATE_521);
        expectBadKeyFail(A256KW, AES_256_CBC_HMAC_SHA_512, ExampleEcKeysFromJws.PUBLIC_521);
    }

    public void testDirAndAes128() throws JoseException
    {
        expectBadKeyFail(DIRECT, AES_128_CBC_HMAC_SHA_256, aesKey(1));
        expectBadKeyFail(DIRECT, AES_128_CBC_HMAC_SHA_256, aesKey(7));
        expectBadKeyFail(DIRECT, AES_128_CBC_HMAC_SHA_256, aesKey(8));
        expectBadKeyFail(DIRECT, AES_128_CBC_HMAC_SHA_256, aesKey(16));
        expectBadKeyFail(DIRECT, AES_128_CBC_HMAC_SHA_256, aesKey(24));
        expectBadKeyFail(DIRECT, AES_128_CBC_HMAC_SHA_256, aesKey(31));
        expectBadKeyFail(DIRECT, AES_128_CBC_HMAC_SHA_256, aesKey(33));
        expectBadKeyFail(DIRECT, AES_128_CBC_HMAC_SHA_256, aesKey(48));
        expectBadKeyFail(DIRECT, AES_128_CBC_HMAC_SHA_256, aesKey(64));
        expectBadKeyFail(DIRECT, AES_128_CBC_HMAC_SHA_256, ExampleRsaJwksFromJwe.APPENDIX_A_2.getPrivateKey());
        expectBadKeyFail(DIRECT, AES_128_CBC_HMAC_SHA_256, ExampleRsaJwksFromJwe.APPENDIX_A_2.getPublicKey());
        expectBadKeyFail(DIRECT, AES_128_CBC_HMAC_SHA_256, ExampleEcKeysFromJws.PRIVATE_521);
        expectBadKeyFail(DIRECT, AES_128_CBC_HMAC_SHA_256, ExampleEcKeysFromJws.PUBLIC_521);
    }

    public void testDirAndAes192() throws JoseException
    {
        expectBadKeyFail(DIRECT, AES_192_CBC_HMAC_SHA_384, aesKey(1));
        expectBadKeyFail(DIRECT, AES_192_CBC_HMAC_SHA_384, aesKey(7));
        expectBadKeyFail(DIRECT, AES_192_CBC_HMAC_SHA_384, aesKey(8));
        expectBadKeyFail(DIRECT, AES_192_CBC_HMAC_SHA_384, aesKey(16));
        expectBadKeyFail(DIRECT, AES_192_CBC_HMAC_SHA_384, aesKey(24));
        expectBadKeyFail(DIRECT, AES_192_CBC_HMAC_SHA_384, aesKey(32));
        expectBadKeyFail(DIRECT, AES_192_CBC_HMAC_SHA_384, aesKey(47));
        expectBadKeyFail(DIRECT, AES_192_CBC_HMAC_SHA_384, aesKey(49));
        expectBadKeyFail(DIRECT, AES_192_CBC_HMAC_SHA_384, aesKey(64));
        expectBadKeyFail(DIRECT, AES_192_CBC_HMAC_SHA_384, ExampleRsaJwksFromJwe.APPENDIX_A_2.getPrivateKey());
        expectBadKeyFail(DIRECT, AES_192_CBC_HMAC_SHA_384, ExampleRsaJwksFromJwe.APPENDIX_A_2.getPublicKey());
        expectBadKeyFail(DIRECT, AES_192_CBC_HMAC_SHA_384, ExampleEcKeysFromJws.PRIVATE_521);
        expectBadKeyFail(DIRECT, AES_192_CBC_HMAC_SHA_384, ExampleEcKeysFromJws.PUBLIC_521);
    }

    public void testDirAndAes256() throws JoseException
    {
        expectBadKeyFail(DIRECT, AES_256_CBC_HMAC_SHA_512, aesKey(1));
        expectBadKeyFail(DIRECT, AES_256_CBC_HMAC_SHA_512, aesKey(7));
        expectBadKeyFail(DIRECT, AES_256_CBC_HMAC_SHA_512, aesKey(8));
        expectBadKeyFail(DIRECT, AES_256_CBC_HMAC_SHA_512, aesKey(16));
        expectBadKeyFail(DIRECT, AES_256_CBC_HMAC_SHA_512, aesKey(24));
        expectBadKeyFail(DIRECT, AES_256_CBC_HMAC_SHA_512, aesKey(32));
        expectBadKeyFail(DIRECT, AES_256_CBC_HMAC_SHA_512, aesKey(48));
        expectBadKeyFail(DIRECT, AES_256_CBC_HMAC_SHA_512, aesKey(63));
        expectBadKeyFail(DIRECT, AES_256_CBC_HMAC_SHA_512, aesKey(65));
        expectBadKeyFail(DIRECT, AES_256_CBC_HMAC_SHA_512, ExampleRsaJwksFromJwe.APPENDIX_A_2.getPrivateKey());
        expectBadKeyFail(DIRECT, AES_256_CBC_HMAC_SHA_512, ExampleRsaJwksFromJwe.APPENDIX_A_2.getPublicKey());
        expectBadKeyFail(DIRECT, AES_256_CBC_HMAC_SHA_512, ExampleEcKeysFromJws.PRIVATE_521);
        expectBadKeyFail(DIRECT, AES_256_CBC_HMAC_SHA_512, ExampleEcKeysFromJws.PUBLIC_521);
    }

    private void expectBadKeyFail(String alg, String enc, Key key)
    {
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setPlaintext("PLAIN OLD TEXT");
        jwe.setAlgorithmHeaderValue(alg);
        jwe.setEncryptionMethodHeaderParameter(enc);
        jwe.setKey(key);

        try
        {
            String cs = jwe.getCompactSerialization();
            fail(cs + " produced when getCompactSerialization should have failed due to bad key");
        }
        catch (JoseException e)
        {
            System.out.println(e);
           // log.debug("Expected exception due to invalid key: " + e);
        }
    }

    private AesKey aesKey(int byteLength)
    {
        return new AesKey(new byte[byteLength]);
    }
}
