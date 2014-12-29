package org.jose4j.jwt.consumer;

import org.jose4j.jwt.JwtClaimsSet;
import org.jose4j.jwt.MalformedClaimException;

/**
 *
 */
public class IssValidator implements ClaimsValidator
{
    private String expectedIssuer;
    private boolean requireIssuer;

    public IssValidator(String expectedIssuer, boolean requireIssuer)
    {
        this.expectedIssuer = expectedIssuer;
        this.requireIssuer = requireIssuer;
    }

    @Override
    public String validate(JwtClaimsSet jwtClaimsSet) throws MalformedClaimException
    {
        String issuer = jwtClaimsSet.getIssuer();

        if (issuer == null)
        {
            return requireIssuer ? "No Issuer (iss) claim present but was expecting " + expectedIssuer: null;
        }

        if (!issuer.equals(expectedIssuer))
        {
            return "Issuer (iss) claim value (" + issuer + ") doesn't match expected value of " + expectedIssuer;
        }

        return null;
    }
}

