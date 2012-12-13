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


import org.jose4j.keys.EcKeyUtil;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.lang.JoseException;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.EllipticCurve;
import java.security.interfaces.ECPublicKey;
import java.io.IOException;


/**
 */
public class EcdsaUsingShaAlgorithm extends BaseSignatureAlgorithm implements JsonWebSignatureAlgorithm
{
    private String curveName;

    public EcdsaUsingShaAlgorithm(String id, String javaAlgo, String curveName)
    {
        super(id, javaAlgo, EcKeyUtil.EC);
        this.curveName = curveName;
    }

    public boolean verifySignature(byte[] signatureBytes, Key key, byte[] securedInputBytes) throws JoseException
    {
        byte[] derEncodedSignatureBytes;
        try
        {
            derEncodedSignatureBytes = convertConcatenatedToDer(signatureBytes);
        }
        catch (IOException e)
        {
            throw new JoseException("Unable to process signature value", e);
        }

        return super.verifySignature(derEncodedSignatureBytes, key, securedInputBytes);
    }

    public byte[] sign(Key key, byte[] securedInputBytes) throws JoseException
    {
        byte[] derEncodedSignatureBytes = super.sign(key, securedInputBytes);
        try
        {
            return convertDerToConcatenated(derEncodedSignatureBytes);
        }
        catch (IOException e)
        {
            throw new JoseException("Unable to convert ", e);
        }
    }

    /*
        The result of an ECDSA signature is the EC point (R, S), where R and S are unsigned (very large) integers.
        The JCA ECDSA signature implementation (sun.security.ec.ECDSASignature) produces and expects a DER encoding
        of R and S while JOSE/JWS wants R and S as a concatenated byte array. XML signatures (best I can tell) treats
        ECDSA same way as JOSE and the code for the two methods that convert to and from DER and concatenated
        R and S was originally taken from org.apache.xml.security.algorithms.implementations.SignatureECDSA in the
        (Apache 2 licensed) Apache Santuario XML Security library. Which seemed like a better idea than trying to
        write it myself or using sun.security.util.Der[Input/Output]Stream as sun.security.ec.ECDSASignature does.
     */

    // Convert the concatenation of R and S into DER encoding
    public static byte[] convertConcatenatedToDer(byte[] concatenatedSignatureBytes) throws IOException
    {
        int rawLen = concatenatedSignatureBytes.length/2;

        int i;

        for (i = rawLen; (i > 0) && (concatenatedSignatureBytes[rawLen - i] == 0); i--);

        int j = i;

        if (concatenatedSignatureBytes[rawLen - i] < 0)
        {
            j += 1;
        }

        int k;

        for (k = rawLen; (k > 0) && (concatenatedSignatureBytes[2*rawLen - k] == 0); k--);

        int l = k;

        if (concatenatedSignatureBytes[2*rawLen - k] < 0)
        {
            l += 1;
        }

        int len = 2 + j + 2 + l;
        if (len > 255)
        {
            throw new IOException("Invalid format of ECDSA signature");
        }
        int offset;
        byte derEncodedSignatureBytes[];
        if (len < 128)
        {
            derEncodedSignatureBytes = new byte[2 + 2 + j + 2 + l];
            offset = 1;
        }
        else
        {
            derEncodedSignatureBytes = new byte[3 + 2 + j + 2 + l];
            derEncodedSignatureBytes[1] = (byte) 0x81;
            offset = 2;
        }

        derEncodedSignatureBytes[0] = 48;
        derEncodedSignatureBytes[offset++] = (byte) len;
        derEncodedSignatureBytes[offset++] = 2;
        derEncodedSignatureBytes[offset++] = (byte) j;

        System.arraycopy(concatenatedSignatureBytes, rawLen - i, derEncodedSignatureBytes, (offset + j) - i, i);

        offset += j;

        derEncodedSignatureBytes[offset++] = 2;
        derEncodedSignatureBytes[offset++] = (byte) l;

        System.arraycopy(concatenatedSignatureBytes, 2*rawLen - k, derEncodedSignatureBytes, (offset + l) - k, k);

        return derEncodedSignatureBytes;
    }

    // Convert the DER encoding of R and S into a concatenation of R and S
    public static byte[] convertDerToConcatenated(byte derEncodedBytes[]) throws IOException
    {

        if (derEncodedBytes.length < 8 || derEncodedBytes[0] != 48)
        {
            throw new IOException("Invalid format of ECDSA signature");
        }

        int offset;
        if (derEncodedBytes[1] > 0)
        {
            offset = 2;
        }
        else if (derEncodedBytes[1] == (byte) 0x81)
        {
            offset = 3;
        }
        else
        {
            throw new IOException("Invalid format of ECDSA signature");
        }

        byte rLength = derEncodedBytes[offset + 1];

        int i;
        for (i = rLength; (i > 0) && (derEncodedBytes[(offset + 2 + rLength) - i] == 0); i--);

        byte sLength = derEncodedBytes[offset + 2 + rLength + 1];

        int j;
        for (j = sLength; (j > 0) && (derEncodedBytes[(offset + 2 + rLength + 2 + sLength) - j] == 0); j--);

        int rawLen = Math.max(i, j);

        if ((derEncodedBytes[offset - 1] & 0xff) != derEncodedBytes.length - offset
            || (derEncodedBytes[offset - 1] & 0xff) != 2 + rLength + 2 + sLength
            || derEncodedBytes[offset] != 2
            || derEncodedBytes[offset + 2 + rLength] != 2)
        {
            throw new IOException("Invalid format of ECDSA signature");
        }
        
        byte concatenatedSignatureBytes[] = new byte[2*rawLen];

        System.arraycopy(derEncodedBytes, (offset + 2 + rLength) - i, concatenatedSignatureBytes, rawLen - i, i);
        System.arraycopy(derEncodedBytes, (offset + 2 + rLength + 2 + sLength) - j, concatenatedSignatureBytes, 2*rawLen - j, j);

        return concatenatedSignatureBytes;
    }

    public void validatePrivateKey(PrivateKey privateKey) throws JoseException
    {
        // todo
    }

    public void validatePublicKey(PublicKey publicKey) throws JoseException
    {
        ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
        ECParameterSpec spec = ecPublicKey.getParams();
        EllipticCurve curve = spec.getCurve();

        String name = EllipticCurves.getName(curve);

        if (!curveName.endsWith(name))
        {
            throw new JoseException(getAlgorithmIdentifier() + "/" + getJavaAlgorithm() + " expects a key using " +
                    curveName + " but was " + name);
        }

    }
}
