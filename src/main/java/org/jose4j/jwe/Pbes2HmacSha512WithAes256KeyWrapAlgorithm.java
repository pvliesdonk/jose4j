/*
 * Copyright 2012-2014 Brian Campbell
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

import org.jose4j.mac.MacUtil;

/**
 */
public class Pbes2HmacSha512WithAes256KeyWrapAlgorithm extends Pbes2HmacShaWithAesKeyWrapAlgorithm
{
    public Pbes2HmacSha512WithAes256KeyWrapAlgorithm()
    {
        super(KeyManagementAlgorithmIdentifiers.PBES2_HS512_A256KW, MacUtil.HMAC_SHA512, new Aes256KeyWrapManagementAlgorithm());
    }
}
