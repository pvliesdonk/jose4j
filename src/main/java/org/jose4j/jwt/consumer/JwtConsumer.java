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
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.keys.resolvers.DecryptionKeyResolver;
import org.jose4j.keys.resolvers.VerificationKeyResolver;
import org.jose4j.lang.ExceptionHelp;
import org.jose4j.lang.JoseException;

import java.security.Key;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 *
 */
public class JwtConsumer
{
    private VerificationKeyResolver verificationKeyResolver;
    private DecryptionKeyResolver decryptionKeyResolver;

    private List<Validator> validators;

    private AlgorithmConstraints jwsAlgorithmConstraints;
    private AlgorithmConstraints jweAlgorithmConstraints;
    private AlgorithmConstraints jweContentEncryptionAlgorithmConstraints;

    private boolean requireSignature = true;
    private boolean requireEncryption;

    private boolean liberalContentTypeHandling;

    private boolean skipSignatureVerification;

    JwtConsumer()
    {
    }

    void setJwsAlgorithmConstraints(AlgorithmConstraints constraints)
    {
        this.jwsAlgorithmConstraints = constraints;
    }

    void setJweAlgorithmConstraints(AlgorithmConstraints constraints)
    {
        this.jweAlgorithmConstraints = constraints;
    }

    void setJweContentEncryptionAlgorithmConstraints(AlgorithmConstraints constraints)
    {
        this.jweContentEncryptionAlgorithmConstraints = constraints;
    }

    void setVerificationKeyResolver(VerificationKeyResolver verificationKeyResolver)
    {
        this.verificationKeyResolver = verificationKeyResolver;
    }

    void setDecryptionKeyResolver(DecryptionKeyResolver decryptionKeyResolver)
    {
        this.decryptionKeyResolver = decryptionKeyResolver;
    }

    void setValidators(List<Validator> validators)
    {
        this.validators = validators;
    }

    void setRequireSignature(boolean requireSignature)
    {
        this.requireSignature = requireSignature;
    }

    void setRequireEncryption(boolean requireEncryption)
    {
        this.requireEncryption = requireEncryption;
    }

    void setLiberalContentTypeHandling(boolean liberalContentTypeHandling)
    {
        this.liberalContentTypeHandling = liberalContentTypeHandling;
    }

    void setSkipSignatureVerification(boolean skipSignatureVerification)
    {
        this.skipSignatureVerification = skipSignatureVerification;
    }

    public JwtClaims processToClaims(String jwt) throws InvalidJwtException
    {
        return process(jwt).getJwtClaims();
    }

    public void processContext(JwtContext jwtContext) throws InvalidJwtException
    {
        boolean hasSignature = false;
        boolean hasEncryption = false;

        ArrayList<JsonWebStructure> originalJoseObjects = new ArrayList<>(jwtContext.getJoseObjects());

        for (int idx = originalJoseObjects.size() - 1 ; idx >= 0 ; idx--)
        {
            List<JsonWebStructure> joseObjects = originalJoseObjects.subList(idx+1, originalJoseObjects.size());
            JsonWebStructure currentJoseObject = originalJoseObjects.get(idx);

            try
            {

                if (currentJoseObject instanceof JsonWebSignature)
                {
                    JsonWebSignature jws = (JsonWebSignature) currentJoseObject;
                    if (!skipSignatureVerification)
                    {
                        Key key = verificationKeyResolver.resolveKey(jws, Collections.unmodifiableList(joseObjects));
                        jws.setKey(key);
                        if (jwsAlgorithmConstraints != null)
                        {
                            jws.setAlgorithmConstraints(jwsAlgorithmConstraints);
                        }

                        if (!jws.verifySignature())
                        {
                            throw new InvalidJwtSignatureException("JWS signature is invalid: " + jws);
                        }
                    }


                    if (!currentJoseObject.getAlgorithmHeaderValue().equals(AlgorithmIdentifiers.NONE))
                    {
                        hasSignature = true;
                    }

                }
                else
                {
                    JsonWebEncryption jwe = (JsonWebEncryption) currentJoseObject;

                    Key key = decryptionKeyResolver.resolveKey(jwe, Collections.unmodifiableList(joseObjects));
                    if (key != null && !key.equals(jwe.getKey()))
                    {
                        throw new InvalidJwtException("The resolved decryption key is different than the one originally used to decrypt the JWE.");
                    }

                    if (jweAlgorithmConstraints != null)
                    {
                        jweAlgorithmConstraints.checkConstraint(jwe.getAlgorithmHeaderValue());
                    }

                    if (jweContentEncryptionAlgorithmConstraints != null)
                    {
                        jweContentEncryptionAlgorithmConstraints.checkConstraint(jwe.getEncryptionMethodHeaderParameter());
                    }

                    hasEncryption = true;
                }
            }
            catch (JoseException e)
            {
                StringBuilder sb = new StringBuilder();
                sb.append("Unable to process");
                if (!joseObjects.isEmpty())
                {
                    sb.append(" nested");
                }
                sb.append(" JOSE object (cause: ").append(e).append("): ").append(currentJoseObject);
                throw new InvalidJwtException(sb.toString(), e);
            }
            catch (InvalidJwtException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                StringBuilder sb = new StringBuilder();
                sb.append("Unexpected exception encountered while processing");
                if (!joseObjects.isEmpty())
                {
                    sb.append(" nested");
                }
                sb.append(" JOSE object (").append(e).append("): ").append(currentJoseObject);
                throw new InvalidJwtException(sb.toString(), e);
            }
        }


        if (requireSignature && !hasSignature)
        {
            throw new InvalidJwtException("The JWT has no signature but the JWT Consumer is configured to require one: " + jwtContext.getJwt());
        }

        if (requireEncryption && !hasEncryption)
        {
            throw new InvalidJwtException("The JWT has no encryption but the JWT Consumer is configured to require it: " + jwtContext.getJwt());
        }

        validate(jwtContext);
    }

    public JwtContext process(String jwt) throws InvalidJwtException
    {
        String workingJwt = jwt;
        JwtClaims jwtClaims = null;
        LinkedList<JsonWebStructure> joseObjects = new LinkedList<>();

        while (jwtClaims == null)
        {
            JsonWebStructure joseObject;
            try
            {
                joseObject = JsonWebStructure.fromCompactSerialization(workingJwt);
                String payload;
                if (joseObject instanceof JsonWebSignature)
                {
                    JsonWebSignature jws = (JsonWebSignature) joseObject;
                    payload = jws.getUnverifiedPayload();
                }
                else
                {
                    JsonWebEncryption jwe = (JsonWebEncryption) joseObject;
                    Key key = decryptionKeyResolver.resolveKey(jwe, Collections.unmodifiableList(joseObjects));
                    jwe.setKey(key);
                    if (jweAlgorithmConstraints != null)
                    {
                        jwe.setAlgorithmConstraints(jweAlgorithmConstraints);
                    }

                    if (jweContentEncryptionAlgorithmConstraints != null)
                    {
                        jwe.setContentEncryptionAlgorithmConstraints(jweContentEncryptionAlgorithmConstraints);
                    }

                    payload = jwe.getPayload();
                }

                if (isNestedJwt(joseObject))
                {
                    workingJwt = payload;
                }
                else
                {
                    try
                    {
                        jwtClaims = JwtClaims.parse(payload);
                    }
                    catch (InvalidJwtException ije)
                    {
                        if (liberalContentTypeHandling)
                        {
                            try
                            {
                                JsonWebStructure.fromCompactSerialization(jwt);
                                workingJwt = payload;
                            }
                            catch (JoseException je)
                            {
                                throw ije;
                            }
                        }
                        else
                        {
                            throw ije;
                        }
                    }
                }

                joseObjects.addFirst(joseObject);
            }
            catch (JoseException e)
            {
                StringBuilder sb = new StringBuilder();
                sb.append("Unable to process");
                if (!joseObjects.isEmpty())
                {
                    sb.append(" nested");
                }
                sb.append(" JOSE object (cause: ").append(e).append("): ").append(workingJwt);
                throw new InvalidJwtException(sb.toString(), e);
            }
            catch (InvalidJwtException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                StringBuilder sb = new StringBuilder();
                sb.append("Unexpected exception encountered while processing");
                if (!joseObjects.isEmpty())
                {
                    sb.append(" nested");
                }
                sb.append(" JOSE object (").append(e).append("): ").append(workingJwt);
                throw new InvalidJwtException(sb.toString(), e);
            }
        }

        JwtContext jwtContext = new JwtContext(jwt, jwtClaims, Collections.unmodifiableList(joseObjects));
        processContext(jwtContext);
        return jwtContext;
    }

    void validate(JwtContext jwtCtx) throws InvalidJwtException
    {
        List<String> issues = new ArrayList<>();
        for (Validator validator : validators)
        {
            String validationResult;
            try
            {
                validationResult  = validator.validate(jwtCtx);
            }
            catch (MalformedClaimException e)
            {
                validationResult = e.getMessage();
            }
            catch (Exception e)
            {
                validationResult = "Unexpected exception thrown from validator " + validator.getClass().getName() + ": " + ExceptionHelp.toStringWithCausesAndAbbreviatedStack(e, this.getClass());
            }

            if (validationResult != null)
            {
                issues.add(validationResult);
            }
        }

        if (!issues.isEmpty())
        {
            InvalidJwtException invalidJwtException = new InvalidJwtException("JWT (claims->"+ jwtCtx.getJwtClaims().getRawJson()+") rejected due to invalid claims.");
            invalidJwtException.setDetails(issues);
            throw invalidJwtException;
        }
    }

    private boolean isNestedJwt(JsonWebStructure joseObject)
    {
        String cty = joseObject.getContentTypeHeaderValue();
        return cty != null && (cty.equalsIgnoreCase("jwt") || cty.equalsIgnoreCase("application/jwt"));
    }

}
