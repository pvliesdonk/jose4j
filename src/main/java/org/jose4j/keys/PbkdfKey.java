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
package org.jose4j.keys;

import org.jose4j.lang.StringUtil;

import javax.crypto.spec.SecretKeySpec;

/**
 */
public class PbkdfKey extends SecretKeySpec
{
    public static final String ALGORITHM = "PBKDF2";

    public PbkdfKey(String password)
    {
        super(StringUtil.getBytesUtf8(password), ALGORITHM);
    }

    // todo a char[] version? Like PBEKeySpec and other java stuff does and for the same reasons
    // "Also note that this class stores passwords as char arrays instead of String objects
    // (which would seem more logical), because the String class is immutable and there is no way to
    // overwrite its internal value when the password stored in it is no longer needed. Hence, this
    // class requests the password as a char array, so it can be overwritten when done."
    // -- http://docs.oracle.com/javase/7/docs/api/javax/crypto/spec/PBEKeySpec.html
}
