package org.jose4j.jwt.consumer;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaimsSet;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.lang.ExceptionHelp;
import org.jose4j.lang.JoseException;

import java.security.Key;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

/**
 *
 */
public class JwtConsumer
{
    private VerificationKeyResolver verificationKeyResolver;
    private DecryptionKeyResolver decryptionKeyResolver;

    private List<ClaimsValidator> claimsValidators;

    private AlgorithmConstraints jwsAlgorithmConstraints;
    private AlgorithmConstraints jweAlgorithmConstraints;
    private AlgorithmConstraints jweContentEncryptionAlgorithmConstraints;

    // todo other custom validators...

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

    void setClaimsValidators(List<ClaimsValidator> claimsValidators)
    {
        this.claimsValidators = claimsValidators;
    }

    public JwtClaimsSet processToClaims(String jwt) throws InvalidJwtException
    {
        return process(jwt).getJwtClaimsSet();
    }

    public ProcessedJwt process(String jwt) throws InvalidJwtException
    {
        ProcessedJwt processedJwt = new ProcessedJwt();

        while (processedJwt.getJwtClaimsSet() == null)
        {
            JsonWebStructure joseObject;
            try
            {
                joseObject = JsonWebStructure.fromCompactSerialization(jwt);

                if (joseObject instanceof JsonWebSignature)
                {
                    JsonWebSignature jws = (JsonWebSignature) joseObject;
                    Key key = verificationKeyResolver.resolveKey(jws, processedJwt.getJoseObjects());
                    jws.setKey(key);
                    if (jwsAlgorithmConstraints != null)
                    {
                        jws.setAlgorithmConstraints(jwsAlgorithmConstraints);
                    }
                    if (!jws.verifySignature())
                    {
                        throw new InvalidJwtException("JWS signature is invalid.");
                    }
                }
                else
                {
                    JsonWebEncryption jwe = (JsonWebEncryption) joseObject;
                    Key key = decryptionKeyResolver.resolveKey(jwe, processedJwt.getJoseObjects());
                    jwe.setKey(key);
                    if (jweAlgorithmConstraints != null)
                    {
                        jwe.setAlgorithmConstraints(jweAlgorithmConstraints);
                    }

                    if (jweContentEncryptionAlgorithmConstraints != null)
                    {
                        jwe.setContentEncryptionAlgorithmConstraints(jweContentEncryptionAlgorithmConstraints);
                    }

                }

                String payload = joseObject.getPayload();

                if (isNestedJwt(joseObject))
                {
                    jwt = payload;
                }
                else
                {
                    processedJwt.jwtClaimsSet = JwtClaimsSet.parse(payload);
                }

                processedJwt.joseObjects.addFirst(joseObject);
            }
            catch (JoseException e)
            {
                StringBuilder sb = new StringBuilder();
                sb.append("Unable to process");
                if (!processedJwt.getJoseObjects().isEmpty())
                {
                    sb.append(" nested");
                }
                sb.append(" JOSE object (cause: ").append(e.getMessage()).append("): ").append(jwt);
                throw new InvalidJwtException(sb.toString(), e);
            }
            catch (Exception e)
            {
                StringBuilder sb = new StringBuilder();
                sb.append("Unexpected exception encountered while processing");
                if (!processedJwt.getJoseObjects().isEmpty())
                {
                    sb.append(" nested");
                }
                sb.append(" JOSE object (").append(e).append("): ").append(jwt);
                throw new InvalidJwtException(sb.toString(), e);
            }
        }

        validateClaims(processedJwt.jwtClaimsSet);

        return processedJwt;
    }

    void validateClaims(JwtClaimsSet jwtClaimsSet) throws InvalidJwtException
    {
        List<String> issues = new ArrayList<>();
        for (ClaimsValidator validator : claimsValidators)
        {
            String validationResult;
            try
            {
                validationResult  = validator.validate(jwtClaimsSet);
            }
            catch (MalformedClaimException e)
            {
                validationResult = e.getMessage();
            }
            catch (Exception e)
            {
                validationResult = "Unexpected exception thrown from validator " + validator.getClass().getName() + ": " + ExceptionHelp.toStringWithCauses(e);
            }

            if (validationResult != null)
            {
                issues.add(validationResult);
            }
        }

        if (!issues.isEmpty())
        {
            InvalidJwtException invalidJwtException = new InvalidJwtException("JWT (claims->"+ jwtClaimsSet.getRawJson()+") rejected due to invalid claims." );
            invalidJwtException.setDetails(issues);
            throw invalidJwtException;
        }
    }

    private boolean isNestedJwt(JsonWebStructure joseObject)
    {
        String cty = joseObject.getHeaders().getStringHeaderValue(HeaderParameterNames.CONTENT_TYPE);
        return cty != null && (cty.equalsIgnoreCase("jwt") || cty.equalsIgnoreCase("application/jwt"));
    }

    public static class ProcessedJwt
    {
        private JwtClaimsSet jwtClaimsSet;
        private LinkedList<JsonWebStructure> joseObjects = new LinkedList<>();

        public JwtClaimsSet getJwtClaimsSet()
        {
            return jwtClaimsSet;
        }

        public List<JsonWebStructure> getJoseObjects()
        {
            return joseObjects;
        }
    }

}
