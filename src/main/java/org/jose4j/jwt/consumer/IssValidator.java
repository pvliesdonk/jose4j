package org.jose4j.jwt.consumer;

import org.jose4j.jwt.MalformedClaimException;

/**
 *
 */
public class IssValidator implements Validator
{
    private String expectedIssuer;
    private boolean requireIssuer;

    public IssValidator(String expectedIssuer, boolean requireIssuer)
    {
        this.expectedIssuer = expectedIssuer;
        this.requireIssuer = requireIssuer;
    }

    @Override
    public String validate(JwtContext jwtContext) throws MalformedClaimException
    {
        String issuer = jwtContext.getJwtClaimsSet().getIssuer();

        if (issuer == null)
        {
            return requireIssuer ? "No Issuer (iss) claim present but was expecting " + expectedIssuer: null;
        }

        if (expectedIssuer != null && !issuer.equals(expectedIssuer))
        {
            return "Issuer (iss) claim value (" + issuer + ") doesn't match expected value of " + expectedIssuer;
        }

        return null;
    }
}

