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
import org.jose4j.jwt.JwtClaimsSet;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.jwx.JsonWebStructure;
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

    public JwtClaimsSet processToClaims(String jwt) throws InvalidJwtException
    {
        return process(jwt).getJwtClaimsSet();
    }

    public JwtContext process(String jwt) throws InvalidJwtException
    {
        JwtClaimsSet jwtClaimsSet = null;
        LinkedList<JsonWebStructure> joseObjects = new LinkedList<>();

        boolean hasSignature = false;
        boolean hasEncryption = false;

        while (jwtClaimsSet == null)
        {
            JsonWebStructure joseObject;
            try
            {
                joseObject = JsonWebStructure.fromCompactSerialization(jwt);

                if (joseObject instanceof JsonWebSignature)
                {
                    JsonWebSignature jws = (JsonWebSignature) joseObject;
                    Key key = verificationKeyResolver.resolveKey(jws, Collections.unmodifiableList(joseObjects));
                    jws.setKey(key);
                    if (jwsAlgorithmConstraints != null)
                    {
                        jws.setAlgorithmConstraints(jwsAlgorithmConstraints);
                    }
                    if (!jws.verifySignature())
                    {
                        throw new InvalidJwtSignatureException("JWS signature is invalid: " + jwt);
                    }

                    if (!jws.getAlgorithmHeaderValue().equals(AlgorithmIdentifiers.NONE))
                    {
                        hasSignature = true;
                    }
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

                    hasEncryption = true;
                }

                String payload = joseObject.getPayload();

                if (isNestedJwt(joseObject))
                {
                    jwt = payload;
                }
                else
                {
                    try
                    {
                        jwtClaimsSet = JwtClaimsSet.parse(payload);
                    }
                    catch (InvalidJwtException ije)
                    {
                        if (liberalContentTypeHandling)
                        {
                            try
                            {
                                JsonWebStructure.fromCompactSerialization(jwt);
                                jwt = payload;
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
                sb.append(" JOSE object (cause: ").append(e).append("): ").append(jwt);
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
                sb.append(" JOSE object (").append(e).append("): ").append(jwt);
                throw new InvalidJwtException(sb.toString(), e);
            }
        }

        if (requireSignature && !hasSignature)
        {
            throw new InvalidJwtException("The JWT has no signature but the JWT Consumer is configured to require one: " + jwt);
        }

        if (requireEncryption && !hasEncryption)
        {
            throw new InvalidJwtException("The JWT has no encryption but the JWT Consumer is configured to require it: " + jwt);
        }

        JwtContext jwtContext = new JwtContext(jwtClaimsSet, Collections.unmodifiableList(joseObjects));
        validate(jwtContext);
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
            InvalidJwtException invalidJwtException = new InvalidJwtException("JWT (claims->"+ jwtCtx.getJwtClaimsSet().getRawJson()+") rejected due to invalid claims.");
            invalidJwtException.setDetails(issues);
            throw invalidJwtException;
        }
    }

    private boolean isNestedJwt(JsonWebStructure joseObject)
    {
        String cty = joseObject.getHeaders().getStringHeaderValue(HeaderParameterNames.CONTENT_TYPE);
        return cty != null && (cty.equalsIgnoreCase("jwt") || cty.equalsIgnoreCase("application/jwt"));
    }

}
