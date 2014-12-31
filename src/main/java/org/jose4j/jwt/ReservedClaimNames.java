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

package org.jose4j.jwt;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 */
public class ReservedClaimNames
{
    public static final String EXPIRATION_TIME = "exp";
    public static final String NOT_BEFORE = "nbf";
    public static final String ISSUED_AT = "iat";
    public static final String ISSUER = "iss";
    public static final String AUDIENCE = "aud";
    public static final String SUBJECT = "sub";
    public static final String JWT_ID = "jti";

    public static final Set<String> INITIAL_REGISTERED_CLAIM_NAMES = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(new String[] {ISSUER, SUBJECT, AUDIENCE, EXPIRATION_TIME, NOT_BEFORE, ISSUED_AT, JWT_ID})));

    /**
     * @deprecated typ went away as a claim name as of jwt draft -12 - it's only a header parameter name
     */
    public static final String TYPE = "typ";
}