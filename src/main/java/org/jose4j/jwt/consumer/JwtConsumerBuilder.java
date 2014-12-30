package org.jose4j.jwt.consumer;

import org.jose4j.jwt.NumericDate;

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
    private IssValidator issValidator;
    private boolean requireSubject;
    private boolean requireJti;
    private NumericDateClaimsValidator dateClaimsValidator = new NumericDateClaimsValidator();

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

    public JwtConsumerBuilder setExpectedIssuer(boolean requireIssuer, String expectedIssuer)
    {
        issValidator = new IssValidator(expectedIssuer, requireIssuer);
        return this;
    }

    public JwtConsumerBuilder setExpectedIssuer(String expectedIssuer)
    {
        return setExpectedIssuer(true, expectedIssuer);
    }

    public JwtConsumerBuilder setRequireSubject()
    {
        this.requireSubject = true;
        return this;
    }

    public JwtConsumerBuilder setRequireJwtId()
    {
        this.requireJti = true;
        return this;
    }

    public JwtConsumerBuilder setRequireExpirationTime()
    {
        dateClaimsValidator.setRequireExp(true);
        return this;
    }

    public JwtConsumerBuilder setRequireIssuedAt()
    {
        dateClaimsValidator.setRequireIat(true);
        return this;
    }

    public JwtConsumerBuilder setRequireNotBefore()
    {
        dateClaimsValidator.setRequireNbf(true);
        return this;
    }

    public JwtConsumerBuilder setEvaluationTime(NumericDate evaluationTime)
    {
        dateClaimsValidator.setEvaluationTime(evaluationTime);
        return this;
    }

    public JwtConsumerBuilder setAllowedClockSkewInSeconds(int secondsOfAllowedClockSkew)
    {
        dateClaimsValidator.setAllowedClockSkewSeconds(secondsOfAllowedClockSkew);
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

        if (issValidator == null)
        {
            issValidator = new IssValidator(null, false);
        }
        claimsValidators.add(issValidator);

        claimsValidators.add(dateClaimsValidator);

        claimsValidators.add(new SubValidator(requireSubject));
        claimsValidators.add(new JtiValidator(requireJti));

        JwtConsumer jwtConsumer = new JwtConsumer();
        jwtConsumer.setClaimsValidators(claimsValidators);
        jwtConsumer.setVerificationKeyResolver(verificationKeyResolver);
        jwtConsumer.setDecryptionKeyResolver(decryptionKeyResolver);
        return jwtConsumer;
    }
}
