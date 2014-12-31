package org.jose4j.jwt.consumer;

import org.jose4j.jwt.JwtClaimsSet;
import org.jose4j.jwt.MalformedClaimException;

/**
 *
 */
public class SubValidator implements Validator
{
    private boolean requireSubject;


    public SubValidator(boolean requireSubject)
    {
        this.requireSubject = requireSubject;
    }

    @Override
    public String validate(JwtContext jwtContext) throws MalformedClaimException
    {
        JwtClaimsSet jwtClaimsSet = jwtContext.getJwtClaimsSet();
        String subject = jwtClaimsSet.getSubject();
        return (subject == null && requireSubject) ?  "No Subject (sub) claim is present." : null;
    }
}
