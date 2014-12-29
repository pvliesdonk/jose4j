package org.jose4j.jwt.consumer;

import java.security.Key;
import java.util.*;

/**
 *
 */
public class JwtConsumerBuilder
{
    private VerificationKeyResolver verificationKeyResolver = new SimpleKeyResolver(null);
    private DecryptionKeyResolver decryptionKeyResolver = new SimpleKeyResolver(null);

    private AudValidator audValidator;

    public JwtConsumerBuilder setVerificationKey(Key verificationKey)
    {
        this.verificationKeyResolver = new SimpleKeyResolver(verificationKey);
        return this;
    }

    public JwtConsumerBuilder setVerificationKeyResolver(VerificationKeyResolver  verificationKeyResolver)
    {
        this.verificationKeyResolver = verificationKeyResolver;
        return this;
    }

    public JwtConsumerBuilder setDecryptionKey(Key decryptionKey)
    {
        this.decryptionKeyResolver = new SimpleKeyResolver(decryptionKey);
        return this;
    }

    public JwtConsumerBuilder setDecryptionKeyResolver(DecryptionKeyResolver  decryptionKeyResolver)
    {
        this.decryptionKeyResolver = decryptionKeyResolver;
        return this;
    }

    public JwtConsumerBuilder setExpectedAudience(String... audience)
    {
        return setExpectedAudience(true, audience);
    }

    public JwtConsumerBuilder setExpectedAudience(boolean requireAudienceClaim, String... audience)
    {
        Set<String> acceptableAudiences = new HashSet<>(Arrays.asList(audience));
        audValidator = new AudValidator(acceptableAudiences, requireAudienceClaim);
        return this;
    }

    public JwtConsumer build()
    {
        List<ClaimsValidator> claimsValidators = new ArrayList<>();

        if (audValidator == null)
        {
            audValidator = new AudValidator(Collections.<String>emptySet(), false);
        }
        claimsValidators.add(audValidator);


        JwtConsumer jwtConsumer = new JwtConsumer();
        jwtConsumer.setVerificationKeyResolver(verificationKeyResolver);
        jwtConsumer.setDecryptionKeyResolver(decryptionKeyResolver);
        jwtConsumer.setClaimsValidators(claimsValidators);
        return jwtConsumer;
    }
}
