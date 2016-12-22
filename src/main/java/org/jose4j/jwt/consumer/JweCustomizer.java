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
package org.jose4j.jwt.consumer;

import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwx.JsonWebStructure;

import java.util.List;

/**
 * A callback interface that provides a hook to call arbitrary methods on the JsonWebEncryption prior
 * to the JwtConsumer using it to decrypt the content.
 */
public interface JweCustomizer
{
    /**
     * Customize the JsonWebEncryption
     * @param jwe the JsonWebEncryption that can be customized prior to decryption
     * @param nestingContext a list of JOSE objects, if any, in which the JWE was nested.
     *                       The last item in the list is the outer most JOSE object (not including the current JWE).
     */
    void customize(JsonWebEncryption jwe, List<JsonWebStructure> nestingContext);
}
