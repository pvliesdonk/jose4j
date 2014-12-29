package org.jose4j.jwt.consumer;

import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaimsSet;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.lang.JoseException;

import java.security.Key;
import java.util.LinkedList;
import java.util.List;

/**
 *
 */
public class JwtConsumer
{
    private VerificationKeyResolver verificationKeyResolver;
    private DecryptionKeyResolver decryptionKeyResolver;

    // TODO alg constraints (with resolvers? but meh)

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
        }

        // TODO validation etc.

        return processedJwt;
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
