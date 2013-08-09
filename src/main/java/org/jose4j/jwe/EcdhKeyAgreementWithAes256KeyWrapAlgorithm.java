package org.jose4j.jwe;

/**
 */
public class EcdhKeyAgreementWithAes256KeyWrapAlgorithm extends EcdhKeyAgreementWithAesKeyWrapAlgorithm implements KeyManagementAlgorithm
{
    public EcdhKeyAgreementWithAes256KeyWrapAlgorithm()
    {
        super(KeyManagementAlgorithmIdentifiers.ECDH_ES_A256KW, new Aes256KeyWrapManagementAlgorithm());
    }
}

