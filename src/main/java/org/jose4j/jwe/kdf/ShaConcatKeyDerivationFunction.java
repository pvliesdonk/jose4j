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

package org.jose4j.jwe.kdf;

import org.apache.commons.codec.CharEncoding;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.StringUtil;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 */
class ShaConcatKeyDerivationFunction
{
    private static final double MAX_REPS = Math.pow(2, 32) - 1;

    private int digestLenght;
    private String digestMethod;

    public static final byte[] ENCRYPTION_LABEL = StringUtil.getBytesUnchecked("Encryption", CharEncoding.US_ASCII);
    public static final byte[] INTEGRITY_LABEL = StringUtil.getBytesUnchecked("Integrity", CharEncoding.US_ASCII);

    public ShaConcatKeyDerivationFunction(int digestLenght)
    {
        this.digestLenght = digestLenght;
        this.digestMethod = "SHA-" + digestLenght;
    }

    public byte[] kdf(byte[] sharedSecret, int keydatalen, byte[] label) throws JoseException
    {
        long reps = getReps(keydatalen);
        MessageDigest digester = getDigester();

        byte[] derivedKeyingMaterial = new byte[0];

        for (int i = 1; i <= reps; i++)
        {
            byte[] counterBytes = ByteUtil.getBytes(i);
            byte[] input = ByteUtil.concat(counterBytes, sharedSecret, label);
            byte[] digest = digester.digest(input);

            derivedKeyingMaterial = ByteUtil.concat(derivedKeyingMaterial, digest); 
        }
                                                                                                            
        int keyDateLenInBytes = keydatalen / 8;
        if (derivedKeyingMaterial.length != keyDateLenInBytes)
        {
            byte[] newKeyMaterial = new byte[keyDateLenInBytes];
            System.arraycopy(derivedKeyingMaterial, 0, newKeyMaterial, 0, keyDateLenInBytes);
            derivedKeyingMaterial = newKeyMaterial;
        }

        return derivedKeyingMaterial;
    }

    private MessageDigest getDigester() throws JoseException
    {
        try
        {
           return MessageDigest.getInstance(digestMethod);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new JoseException("Must have " + digestMethod, e);
        }
    }

    long getReps(int keydatalen) throws JoseException
    {
        double repsD = (float) keydatalen / (float) digestLenght;
        repsD = Math.ceil(repsD);
        long reps = Math.round(repsD);

        if (reps > MAX_REPS)
        {
            String msg = keydatalen + " key length gives reps > (2^32 - 1), so ABORTING: outputing an error indicator and stoping.";
            throw new JoseException(msg);
        }

        return reps;
    }
}
