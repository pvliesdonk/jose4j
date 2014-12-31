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

package org.jose4j.jwe;

/**
*/
public class ContentEncryptionParts
{
    private byte[] iv;
    private byte[] ciphertext;
    private byte[] authenticationTag;

    public ContentEncryptionParts(byte[] iv, byte[] ciphertext, byte[] authenticationTag)
    {
        this.iv = iv;
        this.ciphertext = ciphertext;
        this.authenticationTag = authenticationTag;
    }

    public byte[] getIv()
    {
        return iv;
    }

    public byte[] getCiphertext()
    {
        return ciphertext;
    }

    public byte[] getAuthenticationTag()
    {
        return authenticationTag;
    }
}
