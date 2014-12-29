package org.jose4j.jwt.consumer;

import java.security.Key;

/**
 *
 */
public class JwtConsumerBuilder
{
    private VerificationKeyResolver verificationKeyResolver = new SimpleKeyResolver(null);
    private DecryptionKeyResolver decryptionKeyResolver = new SimpleKeyResolver(null);

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

    public JwtConsumer build()
    {
        JwtConsumer jwtConsumer = new JwtConsumer();
        jwtConsumer.setVerificationKeyResolver(verificationKeyResolver);
        jwtConsumer.setDecryptionKeyResolver(decryptionKeyResolver);
        return jwtConsumer;
    }
}
