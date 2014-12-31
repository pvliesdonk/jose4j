package org.jose4j.jwt.consumer;

import org.jose4j.jwt.MalformedClaimException;

import java.util.List;
import java.util.Set;

/**
 *
 */
public class AudValidator implements Validator
{
    private Set<String> acceptableAudiences;
    private boolean requireAudience;

    public AudValidator(Set<String> acceptableAudiences, boolean requireAudience)
    {
        this.acceptableAudiences = acceptableAudiences;
        this.requireAudience = requireAudience;
    }

    @Override
    public String validate(JwtContext jwtContext) throws MalformedClaimException
    {
        List<String> audiences = jwtContext.getJwtClaimsSet().getAudience();

        if (audiences == null)
        {
            return requireAudience ? "No Audience (aud) claim present." : null;
        }

        boolean ok = false;
        for (String audience : audiences)
        {
            if (acceptableAudiences.contains(audience))
            {
                ok = true;
            }
        }

        if (!ok)
        {
            StringBuilder sb = new StringBuilder();
            sb.append("Audience (aud) claim " ).append(audiences);
            if (acceptableAudiences.isEmpty())
            {
                sb.append(" present in the JWT but no expected audience value(s) were provided to the JWT Consumer.");
            }
            else
            {
                sb.append(" doesn't contain an acceptable identifier.");
            }
            sb.append(" Expected ");
            if (acceptableAudiences.size() == 1)
            {
                sb.append(acceptableAudiences.iterator().next());
            }
            else
            {
                sb.append("one of ").append(acceptableAudiences);
            }
            sb.append(" as an aud value.");

            return sb.toString();
        }

        return null;
    }
}
