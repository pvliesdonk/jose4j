/*
 * Copyright 2012-2015 Brian Campbell
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jose4j.jwt.consumer;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.resolvers.DecryptionKeyResolver;
import org.jose4j.keys.resolvers.VerificationKeyResolver;

import java.security.Key;
import java.util.*;

/**
 *
 */
public class JwtConsumerBuilder
{
    private VerificationKeyResolver verificationKeyResolver = new SimpleKeyResolver(null);
    private DecryptionKeyResolver decryptionKeyResolver = new SimpleKeyResolver(null);

    private AlgorithmConstraints jwsAlgorithmConstraints;
    private AlgorithmConstraints jweAlgorithmConstraints;
    private AlgorithmConstraints jweContentEncryptionAlgorithmConstraints;

    private AudValidator audValidator;
    private IssValidator issValidator;
    private boolean requireSubject;
    private boolean requireJti;
    private NumericDateValidator dateClaimsValidator = new NumericDateValidator();

    private List<Validator> customValidators = new ArrayList<>();

    private boolean requireSignature = true;
    private boolean requireEncryption;

    private boolean skipSignatureVerification = false;

    private boolean liberalContentTypeHandling;

    public JwtConsumerBuilder setEnableRequireEncryption()
    {
        requireEncryption = true;
        return this;
    }

    public JwtConsumerBuilder setDisableRequireSignature()
    {
        requireSignature = false;
        return this;
    }

    public JwtConsumerBuilder setEnableLiberalContentTypeHandling()
    {
        liberalContentTypeHandling = true;
        return this;
    }

    public JwtConsumerBuilder setSkipSignatureVerification()
    {
        skipSignatureVerification = true;
        return this;
    }


    public JwtConsumerBuilder setJwsAlgorithmConstraints(AlgorithmConstraints constraints)
    {
        jwsAlgorithmConstraints = constraints;
        return this;
    }

    public JwtConsumerBuilder setJweAlgorithmConstraints(AlgorithmConstraints constraints)
    {
        jweAlgorithmConstraints = constraints;
        return this;
    }

    public JwtConsumerBuilder setJweContentEncryptionAlgorithmConstraints(AlgorithmConstraints constraints)
    {
        jweContentEncryptionAlgorithmConstraints = constraints;
        return this;
    }

    public JwtConsumerBuilder setVerificationKey(Key verificationKey)
    {
        return setVerificationKeyResolver(new SimpleKeyResolver(verificationKey));
    }

    public JwtConsumerBuilder setVerificationKeyResolver(VerificationKeyResolver  verificationKeyResolver)
    {
        this.verificationKeyResolver = verificationKeyResolver;
        return this;
    }

    public JwtConsumerBuilder setDecryptionKey(Key decryptionKey)
    {
        return setDecryptionKeyResolver(new SimpleKeyResolver(decryptionKey));
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

    public JwtConsumerBuilder setMaxFutureValidityInMinutes(int maxFutureValidityInMinutes)
    {
        dateClaimsValidator.setMaxFutureValidityInMinutes(maxFutureValidityInMinutes);
        return this;
    }


    public JwtConsumerBuilder registerValidator(Validator validator)
    {
        customValidators.add(validator);
        return this;
    }

    public JwtConsumer build()
    {
        List<Validator> validators = new ArrayList<>();
        if (audValidator == null)
        {
            audValidator = new AudValidator(Collections.<String>emptySet(), false);
        }
        validators.add(audValidator);

        if (issValidator == null)
        {
            issValidator = new IssValidator(null, false);
        }
        validators.add(issValidator);

        validators.add(dateClaimsValidator);

        validators.add(new SubValidator(requireSubject));
        validators.add(new JtiValidator(requireJti));

        validators.addAll(customValidators);

        JwtConsumer jwtConsumer = new JwtConsumer();
        jwtConsumer.setValidators(validators);
        jwtConsumer.setVerificationKeyResolver(verificationKeyResolver);
        jwtConsumer.setDecryptionKeyResolver(decryptionKeyResolver);

        jwtConsumer.setJwsAlgorithmConstraints(jwsAlgorithmConstraints);
        jwtConsumer.setJweAlgorithmConstraints(jweAlgorithmConstraints);
        jwtConsumer.setJweContentEncryptionAlgorithmConstraints(jweContentEncryptionAlgorithmConstraints);

        jwtConsumer.setRequireSignature(requireSignature);
        jwtConsumer.setRequireEncryption(requireEncryption);

        jwtConsumer.setLiberalContentTypeHandling(liberalContentTypeHandling);

        jwtConsumer.setSkipSignatureVerification(skipSignatureVerification);

        return jwtConsumer;
    }
}
