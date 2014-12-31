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

package org.jose4j.jwt.consumer;

import org.jose4j.jwt.JwtClaimsSet;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.NumericDate;

/**
 *
 */
public class NumericDateValidator implements Validator
{
    private boolean requireExp;
    private boolean requireIat;
    private boolean requireNbf;
    private NumericDate evaluationTime = NumericDate.now();
    private int allowedClockSkewSeconds = 0;

    public void setRequireExp(boolean requireExp)
    {
        this.requireExp = requireExp;
    }

    public void setRequireIat(boolean requireIat)
    {
        this.requireIat = requireIat;
    }

    public void setRequireNbf(boolean requireNbf)
    {
        this.requireNbf = requireNbf;
    }

    public void setEvaluationTime(NumericDate evaluationTime)
    {
        this.evaluationTime = evaluationTime;
    }

    public void setAllowedClockSkewSeconds(int allowedClockSkewSeconds)
    {
        this.allowedClockSkewSeconds = allowedClockSkewSeconds;
    }

    @Override
    public String validate(JwtContext jwtContext) throws MalformedClaimException
    {
        JwtClaimsSet jwtClaimsSet = jwtContext.getJwtClaimsSet();
        NumericDate expirationTime = jwtClaimsSet.getExpirationTime();
        NumericDate issuedAt = jwtClaimsSet.getIssuedAt();
        NumericDate notBefore = jwtClaimsSet.getNotBefore();

        if (requireExp && expirationTime == null)
        {
            return "No Expiration Time (exp) claim present.";
        }

        if (requireIat && issuedAt == null)
        {
            return "No Issued At (iat) claim present.";
        }

        if (requireNbf && notBefore == null)
        {
            return "No Not Before (nbf) claim present.";
        }

        if (expirationTime != null)
        {
            // if (!evaluationTime.isBefore(expirationTime, allowedClockSkewSeconds))
            if ((evaluationTime.getValue() - allowedClockSkewSeconds) >= expirationTime.getValue())
            {
                return "The JWT is no longer valid - the evaluation time " + evaluationTime + " is on or after the Expiration Time (exp="+expirationTime+") claim value" + skewMessage();
            }

            if (issuedAt != null && expirationTime.isBefore(issuedAt))
            {
                return "The Expiration Time (exp="+expirationTime+") claim value cannot be before the Issued At (iat="+issuedAt+") claim value.";
            }

            if (notBefore != null && expirationTime.isBefore(notBefore))
            {
                return "The Expiration Time (exp="+expirationTime+") claim value cannot be before the Not Before (nbf="+notBefore+") claim value.";
            }
        }

        if (notBefore != null)
        {
            if ((evaluationTime.getValue() + allowedClockSkewSeconds) < notBefore.getValue())
            {
                return "The JWT is not yet valid as the evaluation time " + evaluationTime + " is before the Not Before (nbf="+notBefore+") claim time" + skewMessage();
            }
        }

        return null;
    }

    private String skewMessage()
    {
        if (allowedClockSkewSeconds > 0)
        {
            return " (even when providing " + allowedClockSkewSeconds + " seconds of leeway to account for clock skew).";
        }
        else
        {
            return ".";
        }

    }
}
