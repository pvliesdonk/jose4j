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

package org.jose4j.jwe.kdf;

import org.jose4j.base64url.Base64Url;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.StringUtil;
import org.jose4j.lang.UncheckedJoseException;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 */
class ShaConcatKeyDerivationFunction
{
    private int digestLenght;
    private String digestMethod;
    private Base64Url base64Url;

    public ShaConcatKeyDerivationFunction(int digestLenght)
    {
        this.digestLenght = digestLenght;
        this.digestMethod = "SHA-" + digestLenght;
        this.base64Url = new Base64Url();
    }

    byte[] getDatalenDataFormat(String encodedValue)
    {
        byte[] data = base64Url.base64UrlDecode(encodedValue);
        return prependDatalen(data);
    }

    byte[] prependDatalen(byte[] data)
    {
        if (data == null)
        {
            data = ByteUtil.EMPTY_BYTES;
        }
        byte[] datalen = ByteUtil.getBytes(data.length);
        return ByteUtil.concat(datalen, data);
    }

    public byte[] kdf(byte[] sharedSecret, int keydatalen, String algorithmId, String partyUInfo, String partyVInfo)
    {
        byte[] algorithmIdBytes = StringUtil.getBytesUtf8(algorithmId);
        byte[] partyUInfoBytes = getDatalenDataFormat(partyUInfo);
        byte[] partyVInfoBytes = getDatalenDataFormat(partyVInfo);
        byte[] suppPubInfo = ByteUtil.getBytes(keydatalen);
        byte[] suppPrivInfo =  ByteUtil.EMPTY_BYTES; // or prependDatalen(null);     ?!?!
        return kdf(sharedSecret, keydatalen, algorithmIdBytes, partyUInfoBytes, partyVInfoBytes, suppPubInfo, suppPrivInfo);
    }

    public byte[] kdf(byte[] sharedSecret, int keydatalen, byte[] algorithmId, byte[] partyUInfo, byte[] partyVInfo, byte[] suppPubInfo, byte[] suppPrivInfo)
    {
        byte[] otherInfo = ByteUtil.concat(algorithmId, partyUInfo, partyVInfo, suppPubInfo, suppPrivInfo);
        long reps = getReps(keydatalen);
        MessageDigest messageDigest = getMessageDigest();

        ByteArrayOutputStream derivedByteOutputStream = new ByteArrayOutputStream();
        for (int i = 1; i <= reps; i++)
        {
            byte[] counterBytes = ByteUtil.getBytes(i);
            messageDigest.update(counterBytes);
            messageDigest.update(sharedSecret);
            messageDigest.update(otherInfo);
            byte[] digest = messageDigest.digest();
            derivedByteOutputStream.write(digest, 0, digest.length);
        }

        int keyDateLenInBytes = ByteUtil.getNumberOfBytes(keydatalen);
        byte[] derivedKeyMaterial = derivedByteOutputStream.toByteArray();
        if (derivedKeyMaterial.length != keyDateLenInBytes)
        {
            byte[] newKeyMaterial = new byte[keyDateLenInBytes];
            System.arraycopy(derivedKeyMaterial, 0, newKeyMaterial, 0, keyDateLenInBytes);
            derivedKeyMaterial = newKeyMaterial;
        }

        return derivedKeyMaterial;
    }

    long getReps(int keydatalen)
    {
        double repsD = (float) keydatalen / (float) digestLenght;
        repsD = Math.ceil(repsD);
        return Math.round(repsD);
    }

    private MessageDigest getMessageDigest()
    {
        try
        {
           return MessageDigest.getInstance(digestMethod);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new UncheckedJoseException("Must have " + digestMethod + " but don't.", e);
        }
    }
}
