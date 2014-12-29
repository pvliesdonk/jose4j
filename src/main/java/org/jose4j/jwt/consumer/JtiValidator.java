package org.jose4j.jwt.consumer;

import org.jose4j.jwt.JwtClaimsSet;
import org.jose4j.jwt.MalformedClaimException;

/**
 *
 */
public class JtiValidator implements ClaimsValidator
{
    private boolean requireJti;


    public JtiValidator(boolean requireJti)
    {
        this.requireJti = requireJti;
    }

    @Override
    public String validate(JwtClaimsSet jwtClaimsSet) throws MalformedClaimException
    {
        String subject = jwtClaimsSet.getJwtId();
        return (subject == null && requireJti) ?  "The JWT ID (jti) claim is not present." : null;
    }
}
