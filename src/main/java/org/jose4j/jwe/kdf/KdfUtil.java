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

package org.jose4j.jwe.kdf;

import org.jose4j.base64url.Base64Url;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.StringUtil;

/**
 */
public class KdfUtil
{
    private Base64Url base64Url = new Base64Url();;
    private ConcatKeyDerivationFunction kdf;

    public KdfUtil()
    {
        kdf = new ConcatKeyDerivationFunction("SHA-256");
    }

    public KdfUtil(String provider)
    {
        kdf = new ConcatKeyDerivationFunction("SHA-256", provider);
    }

    public byte[] kdf(byte[] sharedSecret, int keydatalen, String algorithmId, String partyUInfo, String partyVInfo)
    {
        byte[] algorithmIdBytes = prependDatalen(StringUtil.getBytesUtf8(algorithmId));
        byte[] partyUInfoBytes = getDatalenDataFormat(partyUInfo);
        byte[] partyVInfoBytes = getDatalenDataFormat(partyVInfo);
        byte[] suppPubInfo = ByteUtil.getBytes(keydatalen);
        byte[] suppPrivInfo =  ByteUtil.EMPTY_BYTES;

        return kdf.kdf(sharedSecret, keydatalen, algorithmIdBytes, partyUInfoBytes, partyVInfoBytes, suppPubInfo, suppPrivInfo);
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

    byte[] getDatalenDataFormat(String encodedValue)
    {
        byte[] data = base64Url.base64UrlDecode(encodedValue);
        return prependDatalen(data);
    }
}
