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

import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;

/**
 *
 */
public class SubValidator implements Validator
{
    private boolean requireSubject;
    private String expectedSubject;

    public SubValidator(boolean requireSubject)
    {
        this.requireSubject = requireSubject;
    }

    public SubValidator(String expectedSubject)
    {
        this(true);
        this.expectedSubject = expectedSubject;
    }

    @Override
    public String validate(JwtContext jwtContext) throws MalformedClaimException
    {
        JwtClaims jwtClaims = jwtContext.getJwtClaims();
        String subject = jwtClaims.getSubject();
        if (subject == null && requireSubject)
        {
            return "No Subject (sub) claim is present.";
        }
        else if (expectedSubject != null && !expectedSubject.equals(subject))
        {
            return "Subject (sub) claim value (" + subject + ") doesn't match expected value of " + expectedSubject;
        }

        return null;
    }
}
