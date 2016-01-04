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

package org.jose4j.keys.resolvers;

import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.lang.UnresolvableKeyException;

import java.security.Key;
import java.util.List;

/**
 *  A callback interface for resolving the key (by looking at headers like "kid", for example) to use to verify the JWS signature.
 */
public interface VerificationKeyResolver
{
    /**
     * Choose the key to be used for signature verification on the given JWS.
     * @param jws the JsonWebSignature that's about to be verified
     * @param nestingContext a list of JOSE objects, if any, in which the JWS was nested.
     *                       The last item in the list is the outer most JOSE object (not including the current JWS).
     * @return the signature or MAC verification key
     * @throws UnresolvableKeyException if no appropriate key can be found
     */
    Key resolveKey(JsonWebSignature jws, List<JsonWebStructure> nestingContext) throws UnresolvableKeyException;
}
