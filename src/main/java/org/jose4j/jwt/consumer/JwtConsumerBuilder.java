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

import org.jose4j.jca.ProviderContext;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.resolvers.DecryptionKeyResolver;
import org.jose4j.keys.resolvers.VerificationKeyResolver;

import java.security.Key;
import java.util.*;

/**
 * <p>
 * Use the JwtConsumerBuilder to create the appropriate JwtConsumer for your JWT processing needs.
 * </p>
 *
 * The specific validation requirements for a JWT are context dependent, however,
 * it typically advisable to require a expiration time, a trusted issuer, and
 * and audience that identifies your system as the intended recipient.
 * For example, a {@code JwtConsumer} might be set up and used like this:
 *
 * <pre>
 *
 *   JwtConsumer jwtConsumer = new JwtConsumerBuilder()
     .setRequireExpirationTime() // the JWT must have an expiration time
     .setExpectedIssuer("Issuer") // whom the JWT needs to have been issued by
     .setExpectedAudience("Audience") // to whom the JWT is intended for
     .setVerificationKey(publicKey) // verify the signature with the public key
     .build(); // create the JwtConsumer instance

   try
   {
     //  Validate the JWT and process it to the Claims
     JwtClaims jwtClaims = jwtConsumer.processToClaims(jwt);
     System.out.println("JWT validation succeeded! " + jwtClaims);
   }
   catch (InvalidJwtException e)
   {
     // InvalidJwtException will be thrown, if the JWT failed processing or validation in anyway.
     // Hopefully with meaningful explanations(s) about what went wrong.
     System.out.println("Invalid JWT! " + e);
   }
 *
 * </pre>
 *
 */
public class JwtConsumerBuilder
{
    private VerificationKeyResolver verificationKeyResolver = new SimpleKeyResolver(null);
    private DecryptionKeyResolver decryptionKeyResolver = new SimpleKeyResolver(null);

    private AlgorithmConstraints jwsAlgorithmConstraints;
    private AlgorithmConstraints jweAlgorithmConstraints;
    private AlgorithmConstraints jweContentEncryptionAlgorithmConstraints;

    private boolean skipDefaultAudienceValidation;
    private AudValidator audValidator;
    private IssValidator issValidator;
    private boolean requireSubject;
    private String expectedSubject;
    private boolean requireJti;
    private NumericDateValidator dateClaimsValidator = new NumericDateValidator();

    private List<Validator> customValidators = new ArrayList<>();

    private boolean requireSignature = true;
    private boolean requireEncryption;

    private boolean skipSignatureVerification = false;

    private boolean relaxVerificationKeyValidation;

    private boolean relaxDecryptionKeyValidation;

    private boolean skipAllValidators = false;
    private boolean skipAllDefaultValidators = false;

    private boolean liberalContentTypeHandling;

    private ProviderContext jwsProviderContext;
    private ProviderContext jweProviderContext;

    private JwsCustomizer jwsCustomizer;
    private JweCustomizer jweCustomizer;

    /**
     * Creates a new JwtConsumerBuilder, which is set up by default to build a JwtConsumer
     * that requires a signature and will validate the core JWT claims when they
     * are present. The various methods on the builder should be used to customize
     * the JwtConsumer's behavior as appropriate.
     */
    public JwtConsumerBuilder()
    {
        super();
    }

    /**
     * Require that the JWT be encrypted, which is not required by default.
     * @return the same JwtConsumerBuilder
     */
    public JwtConsumerBuilder setEnableRequireEncryption()
    {
        requireEncryption = true;
        return this;
    }

    /**
     * Because integrity protection is needed in most usages of JWT, a signature on the JWT is required by default.
     * Calling this turns that requirement off. It may be necessary, for example, when integrity is ensured though
     * other means like a JWE using a symmetric key management algorithm.
     * @return the same JwtConsumerBuilder
     */
    public JwtConsumerBuilder setDisableRequireSignature()
    {
        requireSignature = false;
        return this;
    }

    /**
     * <p>
     * According to <a href="http://tools.ietf.org/html/rfc7519#section-5.2">section 5.2 of the JWT spec</a>,
     * when nested signing or encryption is employed with a JWT, the "cty" header parameter has to be present and
     * have a value of "JWT" to indicate that a nested JWT is the payload of the outer JWT.
     * </p>
     * <p>
     * Not all JWTs follow that requirement of the spec and this provides a work around for
     * consuming non-compliant JWTs.
     * Calling this method tells the JwtConsumer to be a bit more liberal in processing and
     * make a best effort when the "cty" header isn’t present and the payload doesn't parse as JSON
     * but can be parsed into a JOSE object.
     * </p>
     * @return the same JwtConsumerBuilder
     */
    public JwtConsumerBuilder setEnableLiberalContentTypeHandling()
    {
        liberalContentTypeHandling = true;
        return this;
    }

    /**
     * <p>
     * Skip signature verification.
     * </p>
     * This might be useful in cases where you don't have enough
     * information to set up a validating JWT consumer without cracking open the JWT first. For example,
     * in some contexts you might not know who issued the token without looking at the "iss" claim inside the JWT.
     * In such a case two JwtConsumers cab be used in a "two-pass" validation of sorts - the first JwtConsumer parses the JWT but
     * doesn't validate the signature or claims due to the use of methods like this one and the second JwtConsumers
     * does the actual validation.
     *
     * @return the same JwtConsumerBuilder
     */
    public JwtConsumerBuilder setSkipSignatureVerification()
    {
        skipSignatureVerification = true;
        return this;
    }

    /**
     * <p>
     * Skip all claims validation.
     * </p>
     * This might be useful in cases where you don't have enough
     * information to set up a validating JWT consumer without cracking open the JWT first. For example,
     * in some contexts you might not know who issued the token without looking at the "iss" claim inside the JWT.
     * In such a case two JwtConsumers cab be used in a "two-pass" validation of sorts - the first JwtConsumer parses the JWT but
     * doesn't validate the signature or claims due to the use of methods like this one and the second JwtConsumers
     * does the actual validation.
     *
     * @return the same JwtConsumerBuilder
     */
    public JwtConsumerBuilder setSkipAllValidators()
    {
        skipAllValidators = true;
        return this;
    }

    /**
     * Skip all the default claim validation but not those provided via {@link #registerValidator(Validator)}.
     * @return the same JwtConsumerBuilder
     */
    public JwtConsumerBuilder setSkipAllDefaultValidators()
    {
        skipAllDefaultValidators = true;
        return this;
    }

    /**
     * Set the JWS algorithm constraints to be applied when processing the JWT.
     * @param constraints the AlgorithmConstraints to use for JWS processing
     * @return the same JwtConsumerBuilder
     */
    public JwtConsumerBuilder setJwsAlgorithmConstraints(AlgorithmConstraints constraints)
    {
        jwsAlgorithmConstraints = constraints;
        return this;
    }

    /**
     * Set the JWE algorithm constraints to be applied to key management when processing the JWT.
     * @param constraints the AlgorithmConstraints to use for JWE key management algorithm processing
     * @return the same JwtConsumerBuilder
     */
    public JwtConsumerBuilder setJweAlgorithmConstraints(AlgorithmConstraints constraints)
    {
        jweAlgorithmConstraints = constraints;
        return this;
    }

    /**
     * Set the JWE algorithm constraints to be applied to content encryption when processing the JWT.
     * @param constraints the AlgorithmConstraints to use for JWE content encryption processing
     * @return the same JwtConsumerBuilder
     */
    public JwtConsumerBuilder setJweContentEncryptionAlgorithmConstraints(AlgorithmConstraints constraints)
    {
        jweContentEncryptionAlgorithmConstraints = constraints;
        return this;
    }

    /**
     * Set the key to be used for JWS signature/MAC verification.
     * @param verificationKey the verification key.
     * @return the same JwtConsumerBuilder
     */
    public JwtConsumerBuilder setVerificationKey(Key verificationKey)
    {
        return setVerificationKeyResolver(new SimpleKeyResolver(verificationKey));
    }

    /**
     * Set the VerificationKeyResolver to use to select the key for JWS signature/MAC verification.
     * A VerificationKeyResolver enables a verification key to be chosen dynamically based on more
     * information, like the JWS headers, about the message being processed.
     * @param verificationKeyResolver the VerificationKeyResolver
     * @return the same JwtConsumerBuilder
     * @see org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver
     * @see org.jose4j.keys.resolvers.JwksVerificationKeyResolver
     * @see org.jose4j.keys.resolvers.X509VerificationKeyResolver
     */
    public JwtConsumerBuilder setVerificationKeyResolver(VerificationKeyResolver verificationKeyResolver)
    {
        this.verificationKeyResolver = verificationKeyResolver;
        return this;
    }

    /**
     * Set the key to be used for JWE decryption.
     * @param decryptionKey the decryption key.
     * @return the same JwtConsumerBuilder
     */
    public JwtConsumerBuilder setDecryptionKey(Key decryptionKey)
    {
        return setDecryptionKeyResolver(new SimpleKeyResolver(decryptionKey));
    }

    /**
     * Set the DecryptionKeyResolver to use to select the key for JWE decryption.
     * A DecryptionKeyResolver enables a decryption key to be chosen dynamically based on more
     * information, like the JWE headers, about the message being processed.
     * @param decryptionKeyResolver the VerificationKeyResolver
     * @return the same JwtConsumerBuilder
     * @see org.jose4j.keys.resolvers.JwksDecryptionKeyResolver
     */
    public JwtConsumerBuilder setDecryptionKeyResolver(DecryptionKeyResolver  decryptionKeyResolver)
    {
        this.decryptionKeyResolver = decryptionKeyResolver;
        return this;
    }

    /**
     * <p>
     * Set the audience value(s) to use when validating the audience ("aud") claim of a JWT
     * and require that an audience claim be present.
     * Audience validation will succeed, if any one of the provided values is equal to any one
     * of the values of the "aud" claim in the JWT.
     * </p>
     * <p>
     * From <a href="http://tools.ietf.org/html/rfc7519#section-4.1.3">Section 4.1.3 of RFC 7519</a>:
     *  The "aud" (audience) claim identifies the recipients that the JWT is
     * intended for.  Each principal intended to process the JWT MUST
     * identify itself with a value in the audience claim.  If the principal
     * processing the claim does not identify itself with a value in the
     * "aud" claim when this claim is present, then the JWT MUST be
     * rejected.  In the general case, the "aud" value is an array of case-
     * sensitive strings, each containing a StringOrURI value.  In the
     * special case when the JWT has one audience, the "aud" value MAY be a
     * single case-sensitive string containing a StringOrURI value.  The
     * interpretation of audience values is generally application specific.
     * Use of this claim is OPTIONAL.
     * </p>
     * <p>Equivalent to calling {@link #setExpectedAudience(boolean, String...)} with {@code true} as the first argument.</p>
     * @param audience the audience value(s) that identify valid recipient(s) of a JWT
     * @return the same JwtConsumerBuilder
     */
    public JwtConsumerBuilder setExpectedAudience(String... audience)
    {
        return setExpectedAudience(true, audience);
    }

    /**
     * Set the audience value(s) to use when validating the audience ("aud") claim of a JWT.
     * Audience validation will succeed, if any one of the provided values is equal to any one
     * of the values of the "aud" claim in the JWT.
     * </p>
     * <p>
     * If present, the audience claim will always be validated (unless explicitly disabled). The {@code requireAudienceClaim} parameter
     * can be used to indicate whether or not the presence of the audience claim is required. In most cases
     *  {@code requireAudienceClaim} should be {@code true}.
     * </p>
     * <p>
     * From <a href="http://tools.ietf.org/html/rfc7519#section-4.1.3">Section 4.1.3 of RFC 7519</a>:
     *  The "aud" (audience) claim identifies the recipients that the JWT is
     * intended for.  Each principal intended to process the JWT MUST
     * identify itself with a value in the audience claim.  If the principal
     * processing the claim does not identify itself with a value in the
     * "aud" claim when this claim is present, then the JWT MUST be
     * rejected.  In the general case, the "aud" value is an array of case-
     * sensitive strings, each containing a StringOrURI value.  In the
     * special case when the JWT has one audience, the "aud" value MAY be a
     * single case-sensitive string containing a StringOrURI value.  The
     * interpretation of audience values is generally application specific.
     * Use of this claim is OPTIONAL.
     * </p>
     * @param requireAudienceClaim true, if an audience claim has to be present for validation to succeed. false, otherwise
     * @param audience the audience value(s) that identify valid recipient(s) of a JWT
     * @return the same JwtConsumerBuilder
     */
    public JwtConsumerBuilder setExpectedAudience(boolean requireAudienceClaim, String... audience)
    {
        Set<String> acceptableAudiences = new HashSet<>(Arrays.asList(audience));
        audValidator = new AudValidator(acceptableAudiences, requireAudienceClaim);
        return this;
    }

    /**
     * Skip the default audience validation.
     * @return the same JwtConsumerBuilder
     */
    public JwtConsumerBuilder setSkipDefaultAudienceValidation()
    {
        skipDefaultAudienceValidation = true;
        return this;
    }

    /**
     * Indicates whether or not the issuer ("iss") claim is required and optionally what the expected value is.
     * @param requireIssuer ture if issuer is required, false otherwise
     * @param expectedIssuer the value that the issuer claim must have to pass validation, {@code null} means that any value is acceptable
     * @return the same JwtConsumerBuilder
     */
    public JwtConsumerBuilder setExpectedIssuer(boolean requireIssuer, String expectedIssuer)
    {
        issValidator = new IssValidator(expectedIssuer, requireIssuer);
        return this;
    }

    /**
     * Indicates the expected value of the issuer ("iss") claim and that the claim is required.
     * Equivalent to calling {@link #setExpectedIssuer(boolean, String)} with {@code true} as the first argument.
     * @param expectedIssuer the value that the issuer claim must have to pass validation, {@code null} means that any value is acceptable
     * @return the same JwtConsumerBuilder
     */
    public JwtConsumerBuilder setExpectedIssuer(String expectedIssuer)
    {
        return setExpectedIssuer(true, expectedIssuer);
    }

    /**
     * Require that a subject ("sub") claim be present in the JWT.
     * @return the same JwtConsumerBuilder
     */
    public JwtConsumerBuilder setRequireSubject()
    {
        this.requireSubject = true;
        return this;
    }

    /**
     * Require that a subject ("sub") claim be present in the JWT and that its value
     * match that of the provided subject.
     * The subject ("sub") claim is defined in <a href="http://tools.ietf.org/html/rfc7519#section-4.1.2">Section 4.1.2 of RFC 7519</a>.
     *
     * @param subject the required value of the subject claim.
     * @return the same JwtConsumerBuilder
     */
    public JwtConsumerBuilder setExpectedSubject(String subject)
    {
        this.expectedSubject = subject;
        return setRequireSubject();
    }

    /**
     * Require that a <a href="http://tools.ietf.org/html/rfc7519#section-4.1.7">JWT ID ("jti") claim</a> be present in the JWT.
     * @return the same JwtConsumerBuilder
     */
    public JwtConsumerBuilder setRequireJwtId()
    {
        this.requireJti = true;
        return this;
    }

    /**
     * Require that the JWT contain an <a href="http://tools.ietf.org/html/rfc7519#section-4.1.4">expiration time ("exp") claim</a>.
     * The expiration time is always checked when present (unless explicitly disabled) but
     * calling this method strengthens the requirement such that a JWT without an expiration time
     * will not pass validation.
     * @return the same JwtConsumerBuilder
     */
    public JwtConsumerBuilder setRequireExpirationTime()
    {
        dateClaimsValidator.setRequireExp(true);
        return this;
    }

    /**
     * Require that the JWT contain an <a href="http://tools.ietf.org/html/rfc7519#section-4.1.6">issued at time ("iat") claim</a>.
     * @return the same JwtConsumerBuilder
     */
    public JwtConsumerBuilder setRequireIssuedAt()
    {
        dateClaimsValidator.setRequireIat(true);
        return this;
    }

    /**
     * Require that the JWT contain an <a href="http://tools.ietf.org/html/rfc7519#section-4.1.5">not before ("nbf") claim</a>.
     * @return the same JwtConsumerBuilder
     */
    public JwtConsumerBuilder setRequireNotBefore()
    {
        dateClaimsValidator.setRequireNbf(true);
        return this;
    }

    /**
     * Set the time used to validate the expiration time, issued at time, and not before time claims.
     * If not set (or null), the current time will be used to validate the date claims.
     * @param evaluationTime the time with respect to which to validate the date claims.
     * @return the same JwtConsumerBuilder
     */
    public JwtConsumerBuilder setEvaluationTime(NumericDate evaluationTime)
    {
        dateClaimsValidator.setEvaluationTime(evaluationTime);
        return this;
    }

    /**
     * Set the amount of clock skew to allow for when validate the expiration time, issued at time, and not before time claims.
     * @param secondsOfAllowedClockSkew the number of seconds of leniency in date comparisons
     * @return the same JwtConsumerBuilder
     */
    public JwtConsumerBuilder setAllowedClockSkewInSeconds(int secondsOfAllowedClockSkew)
    {
        dateClaimsValidator.setAllowedClockSkewSeconds(secondsOfAllowedClockSkew);
        return this;
    }

    /**
     * Set maximum on how far in the future the "exp" claim can be.
     * @param maxFutureValidityInMinutes how far is too far (in minutes)
     * @return the same JwtConsumerBuilder
     */
    public JwtConsumerBuilder setMaxFutureValidityInMinutes(int maxFutureValidityInMinutes)
    {
        dateClaimsValidator.setMaxFutureValidityInMinutes(maxFutureValidityInMinutes);
        return this;
    }

    /**
     * Bypass the strict checks on the verification key. This might be needed, for example, if the
     * JWT issuer is using 1024 bit RSA keys or HMAC secrets that are too small (smaller than the size of the hash output).
     * @return the same JwtConsumerBuilder
     */
    public JwtConsumerBuilder setRelaxVerificationKeyValidation()
    {
        relaxVerificationKeyValidation = true;
        return this;
    }

    /**
     * Bypass the strict checks on the decryption key.
     * @return the same JwtConsumerBuilder
     */
    public JwtConsumerBuilder setRelaxDecryptionKeyValidation()
    {
        relaxDecryptionKeyValidation = true;
        return this;
    }

    /**
     * Custom Validator implementations, which will be invoked when the {@code JwtConsumer} is validating the JWT claims.
     * @param validator the validator
     * @return the same JwtConsumerBuilder
     */
    public JwtConsumerBuilder registerValidator(Validator validator)
    {
        customValidators.add(validator);
        return this;
    }

    /**
     * Set a callback JwsCustomizer that provides a hook to call arbitrary methods on the/any JsonWebSignature prior
     * to the JwsConsumer using it to verify the signature.
     * This might be used, for example, to allow for
     * critical ("crit") headers vai {@link org.jose4j.jwx.JsonWebStructure#setKnownCriticalHeaders(String...)}
     * that the caller knows how to handle and needs to tell the JwsConsumer to allow them.
     * @param jwsCustomizer the JwsCustomizer implementation
     * @return the same JwtConsumerBuilder
     */
    public JwtConsumerBuilder setJwsCustomizer(JwsCustomizer jwsCustomizer)
    {
        this.jwsCustomizer = jwsCustomizer;
        return this;
    }

    /**
     * Set a callback JweCustomizer that provides a hook to call arbitrary methods on the/any JsonWebEncryption prior
     * to the JwsConsumer using it for decryption.
     * This might be used, for example, to allow for
     * critical ("crit") headers vai {@link org.jose4j.jwx.JsonWebStructure#setKnownCriticalHeaders(String...)}
     * that the caller knows how to handle and needs to tell the JwsConsumer to allow them.
     * @param jweCustomizer the JweCustomizer implementation
     * @return the same JwtConsumerBuilder
     */
    public JwtConsumerBuilder setJweCustomizer(JweCustomizer jweCustomizer)
    {
        this.jweCustomizer = jweCustomizer;
        return this;
    }

    /**
     * Sets the {@link ProviderContext} for any JWS operations to be done by the JwtConsumer being built.
     * This allows for
     * a particular Java Cryptography Architecture provider to be indicated by name to be used
     * for signature/MAC verification operations.
     *
     * @param jwsProviderContext the ProviderContext object indicating the Java Cryptography Architecture provider
     * to be used for JWS signature/MAC verification operations when consuming a JWT.
     * @return the same JwtConsumerBuilder
     */
    public JwtConsumerBuilder setJwsProviderContext(ProviderContext jwsProviderContext)
    {
        this.jwsProviderContext = jwsProviderContext;
        return this;
    }

    /**
     * Sets the {@link ProviderContext} for any JWE operations to be done by the JwtConsumer being built.
     * This allows for
     * a particular Java Cryptography Architecture provider to be indicated by name to be used
     * for decryption and related operations.
     *
     * @param jweProviderContext the ProviderContext object indicating the Java Cryptography Architecture provider
     * to be used for decryption and related operations operations when consuming a JWT.
     * @return the same JwtConsumerBuilder
     */
    public JwtConsumerBuilder setJweProviderContext(ProviderContext jweProviderContext)
    {
        this.jweProviderContext = jweProviderContext;
        return this;
    }

    /**
     * Create the JwtConsumer with the options provided to the builder.
     * @return the JwtConsumer
     */
    public JwtConsumer build()
    {
        List<Validator> validators = new ArrayList<>();
        if (!skipAllValidators)
        {
            if (!skipAllDefaultValidators)
            {
                if (!skipDefaultAudienceValidation)
                {
                    if (audValidator == null)
                    {
                        audValidator = new AudValidator(Collections.<String>emptySet(), false);
                    }
                    validators.add(audValidator);
                }

                if (issValidator == null)
                {
                    issValidator = new IssValidator(null, false);
                }
                validators.add(issValidator);

                validators.add(dateClaimsValidator);

                SubValidator subValidator = expectedSubject == null ? new SubValidator(requireSubject) : new SubValidator(expectedSubject);
                validators.add(subValidator);
                validators.add(new JtiValidator(requireJti));
            }

            validators.addAll(customValidators);
        }

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

        jwtConsumer.setRelaxVerificationKeyValidation(relaxVerificationKeyValidation);
        jwtConsumer.setRelaxDecryptionKeyValidation(relaxDecryptionKeyValidation);

        jwtConsumer.setJwsCustomizer(jwsCustomizer);
        jwtConsumer.setJweCustomizer(jweCustomizer);

        jwtConsumer.setJwsProviderContext(jwsProviderContext);
        jwtConsumer.setJweProviderContext(jweProviderContext);

        return jwtConsumer;
    }
}
