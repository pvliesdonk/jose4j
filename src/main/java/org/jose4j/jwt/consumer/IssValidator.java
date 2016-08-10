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

import org.jose4j.jwt.MalformedClaimException;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 *
 */
public class IssValidator implements Validator
{
    private Set<String> expectedIssuers;
    private boolean requireIssuer;

    public IssValidator(String expectedIssuer, boolean requireIssuer)
    {
        if (expectedIssuer != null)
        {
            this.expectedIssuers = Collections.singleton(expectedIssuer);
        }
        this.requireIssuer = requireIssuer;
    }

    public IssValidator(boolean requireIssuer, String... expectedIssuers)
    {
        this.requireIssuer = requireIssuer;
        if (expectedIssuers != null && expectedIssuers.length > 0)
        {
            this.expectedIssuers = new HashSet<>();
            Collections.addAll(this.expectedIssuers, expectedIssuers);
        }
    }

    @Override
    public String validate(JwtContext jwtContext) throws MalformedClaimException
    {
        String issuer = jwtContext.getJwtClaims().getIssuer();

        if (issuer == null)
        {
            return requireIssuer ? "No Issuer (iss) claim present but was expecting " + expectedValue() : null;
        }

        if (expectedIssuers != null && !expectedIssuers.contains(issuer))
        {
            return "Issuer (iss) claim value (" + issuer + ") doesn't match expected value of " + expectedValue();
        }

        return null;
    }

    private String expectedValue()
    {
        return expectedIssuers.size() == 1 ? expectedIssuers.iterator().next() : "one of " + expectedIssuers;
    }
}

