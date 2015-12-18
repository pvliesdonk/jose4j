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

package org.jose4j.jwe.kdf;

import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.HashUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;

/**
 * An implementation of Concatenation Key Derivation Function (aka Concat KDF or ConcatKDF)
 * from Section 5.8.1 of National Institute of Standards and Technology (NIST),
 * "Recommendation for Pair-Wise Key Establishment Schemes Using Discrete Logarithm Cryptography",
 * NIST Special Publication 800-56A, Revision 2, May 2013.
 */
public class ConcatKeyDerivationFunction
{
    private static final Logger log = LoggerFactory.getLogger(ConcatKeyDerivationFunction.class);

    private int digestLength;
    private MessageDigest messageDigest;

    public ConcatKeyDerivationFunction(String hashAlgoritm)
    {
        messageDigest = HashUtil.getMessageDigest(hashAlgoritm);
        init();
    }

    public ConcatKeyDerivationFunction(String hashAlgoritm, String provider)
    {
        messageDigest = HashUtil.getMessageDigest(hashAlgoritm, provider);
        init();
    }

    private void init()
    {
        digestLength = ByteUtil.bitLength(messageDigest.getDigestLength());

        if (traceLog()) { log.trace("Hash Algorithm: {} with hashlen: {} bits", messageDigest.getAlgorithm(), digestLength); }
    }

    public byte[] kdf(byte[] sharedSecret, int keydatalen, byte[] algorithmId, byte[] partyUInfo, byte[] partyVInfo, byte[] suppPubInfo, byte[] suppPrivInfo)
    {
        if (traceLog())
        {
            StringBuilder msg = new StringBuilder();
            msg.append("KDF:").append("\n");
            msg.append("  z: ").append(ByteUtil.toDebugString(sharedSecret)).append("\n");
            msg.append("  keydatalen: ").append(keydatalen);
            msg.append("  algorithmId: ").append(ByteUtil.toDebugString(algorithmId)).append("\n");
            msg.append("  partyUInfo: ").append(ByteUtil.toDebugString(partyUInfo)).append("\n");
            msg.append("  partyVInfo: ").append(ByteUtil.toDebugString(partyVInfo)).append("\n");
            msg.append("  suppPubInfo: ").append(ByteUtil.toDebugString(suppPubInfo)).append("\n");
            msg.append("  suppPrivInfo: ").append(ByteUtil.toDebugString(suppPrivInfo));
            log.trace(msg.toString());
        }

        byte[] otherInfo = ByteUtil.concat(algorithmId, partyUInfo, partyVInfo, suppPubInfo, suppPrivInfo);
        return kdf(sharedSecret, keydatalen, otherInfo);
    }

    public byte[] kdf(byte[] sharedSecret, int keydatalen, byte[] otherInfo)
    {
        long reps = getReps(keydatalen);
        if (traceLog())
        {
            log.trace("reps: {}", String.valueOf(reps));
            log.trace("otherInfo: {}", ByteUtil.toDebugString(otherInfo));
        }

        ByteArrayOutputStream derivedByteOutputStream = new ByteArrayOutputStream();
        for (int i = 1; i <= reps; i++)
        {
            byte[] counterBytes = ByteUtil.getBytes(i);

            if (traceLog())
            {
                log.trace("rep {} hashing ", i);
                log.trace(" counter: {}", ByteUtil.toDebugString(counterBytes));
                log.trace(" z: {}", ByteUtil.toDebugString(sharedSecret));
                log.trace(" otherInfo: {}", ByteUtil.toDebugString(otherInfo));
            }

            messageDigest.update(counterBytes);
            messageDigest.update(sharedSecret);
            messageDigest.update(otherInfo);
            byte[] digest = messageDigest.digest();
            if (traceLog()) { log.trace(" k({}): {}", i, ByteUtil.toDebugString(digest));}
            derivedByteOutputStream.write(digest, 0, digest.length);
        }

        int keyDateLenInBytes = ByteUtil.byteLength(keydatalen);
        byte[] derivedKeyMaterial = derivedByteOutputStream.toByteArray();
        if (traceLog()) { log.trace("derived key material: {}", ByteUtil.toDebugString(derivedKeyMaterial));}
        if (derivedKeyMaterial.length != keyDateLenInBytes)
        {
            byte[] newKeyMaterial  = ByteUtil.subArray(derivedKeyMaterial, 0, keyDateLenInBytes);
            if (traceLog()) {log.trace("first {} bits of derived key material: {}", keydatalen, ByteUtil.toDebugString(newKeyMaterial));}
            derivedKeyMaterial = newKeyMaterial;
        }

        if (traceLog()) { log.trace("final derived key material: {}", ByteUtil.toDebugString(derivedKeyMaterial)); }
        return derivedKeyMaterial;
    }

    long getReps(int keydatalen)
    {
        double repsD = (float) keydatalen / (float) digestLength;
        repsD = Math.ceil(repsD);
        return (int) repsD;
    }

    private boolean traceLog()
    {
        return false && log.isTraceEnabled();
    }
}
