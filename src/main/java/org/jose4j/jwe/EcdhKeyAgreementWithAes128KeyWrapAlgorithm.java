package org.jose4j.jwe;

/**
 */
public class EcdhKeyAgreementWithAes128KeyWrapAlgorithm extends EcdhKeyAgreementWithAesKeyWrapAlgorithm implements KeyManagementAlgorithm
{
    public EcdhKeyAgreementWithAes128KeyWrapAlgorithm()
    {
        super(KeyManagementAlgorithmIdentifiers.ECDH_ES_A128KW, new Aes128KeyWrapManagementAlgorithm());
    }
}
