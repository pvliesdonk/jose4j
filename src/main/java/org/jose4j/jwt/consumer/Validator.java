package org.jose4j.jwt.consumer;

import org.jose4j.jwt.MalformedClaimException;


/**
 *
 */
public interface Validator
{
    /**
     * @param jwtContext the JWT context
     * @return a description of the problem or null, if valid
     */
    public String validate(JwtContext jwtContext) throws MalformedClaimException;
}
