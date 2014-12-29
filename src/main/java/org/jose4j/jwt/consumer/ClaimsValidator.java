package org.jose4j.jwt.consumer;

import org.jose4j.jwt.JwtClaimsSet;
import org.jose4j.jwt.MalformedClaimException;

/**
 *
 */
public interface ClaimsValidator
{
    /**
     *
     * @param jwtClaimsSet the JWT Claims Set
     * @return a description of the problem or null, if valid
     */
    public String validate(JwtClaimsSet jwtClaimsSet) throws MalformedClaimException;
}
