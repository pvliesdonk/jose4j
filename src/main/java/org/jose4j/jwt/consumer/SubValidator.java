package org.jose4j.jwt.consumer;

import org.jose4j.jwt.JwtClaimsSet;
import org.jose4j.jwt.MalformedClaimException;

/**
 *
 */
public class SubValidator implements ClaimsValidator
{
    private boolean requireSubject;


    public SubValidator(boolean requireSubject)
    {
        this.requireSubject = requireSubject;
    }

    @Override
    public String validate(JwtClaimsSet jwtClaimsSet) throws MalformedClaimException
    {
        String subject = jwtClaimsSet.getSubject();
        return (subject == null && requireSubject) ?  "No Subject (sub) claim is present." : null;
    }
}
