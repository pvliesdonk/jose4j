package org.jose4j.jwt.consumer;

import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.JsonWebStructure;

import java.security.Key;
import java.util.List;

/**
 *
 */
public interface VerificationKeyResolver
{
    Key resolveKey(JsonWebSignature jws, List<JsonWebStructure> nestingContext);
}
