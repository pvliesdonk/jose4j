package org.jose4j.jwt.consumer;

import org.jose4j.jwt.MalformedClaimException;

/**
 *
 */
public class JtiValidator implements Validator
{
    private boolean requireJti;


    public JtiValidator(boolean requireJti)
    {
        this.requireJti = requireJti;
    }

    @Override
    public String validate(JwtContext jwtContext) throws MalformedClaimException
    {
        String subject = jwtContext.getJwtClaimsSet().getJwtId();
        return (subject == null && requireJti) ?  "The JWT ID (jti) claim is not present." : null;
    }
}
