package org.jose4j.jwt.consumer;

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

    // TODO alg constraints (with resolvers? but meh)

    // todo other custom validators...

    JwtConsumer()
    {
    }

    void setVerificationKeyResolver(VerificationKeyResolver verificationKeyResolver)
    {
        this.verificationKeyResolver = verificationKeyResolver;
    }

    void setDecryptionKeyResolver(DecryptionKeyResolver decryptionKeyResolver)
    {
        this.decryptionKeyResolver = decryptionKeyResolver;
    }

    public void setClaimsValidators(List<ClaimsValidator> claimsValidators)
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
                }

                processedJwt.joseObjects.addFirst(joseObject);

                String payload = joseObject.getPayload();
                if (isNestedJwt(joseObject))
                {
                    jwt = payload;
                }
                else
                {
                    processedJwt.jwtClaimsSet = JwtClaimsSet.parse(payload);
                }
            }
            catch (JoseException e)
            {
                throw new InvalidJwtException("Unable to process JOSE object (cause: "+e.getMessage()+"): " + jwt, e);
            }
            catch (Exception e)
            {
                throw new InvalidJwtException("Unexpected exception encountered while process JOSE object(s) ("+e+"): " + jwt, e);
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
