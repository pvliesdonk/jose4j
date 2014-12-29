package org.jose4j.jwt.consumer;


import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwx.JsonWebStructure;

import java.security.Key;
import java.util.List;

/**
 *
 */
public interface DecryptionKeyResolver
{
    Key resolveKey(JsonWebEncryption jwe, List<JsonWebStructure> nestingContext);
}
