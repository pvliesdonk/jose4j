package org.jose4j.jwe;

/**
 */
public class EcdhKeyAgreementWithAes192KeyWrapAlgorithm extends EcdhKeyAgreementWithAesKeyWrapAlgorithm implements KeyManagementAlgorithm
{
    public EcdhKeyAgreementWithAes192KeyWrapAlgorithm()
    {
        super(KeyManagementAlgorithmIdentifiers.ECDH_ES_A192KW, new Aes192KeyWrapManagementAlgorithm());
    }
}