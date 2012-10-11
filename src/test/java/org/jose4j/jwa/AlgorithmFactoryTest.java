package org.jose4j.jwa;

import junit.framework.TestCase;
import org.jose4j.jws.JsonWebSignatureAlgorithm;

/**
 */
public class AlgorithmFactoryTest extends TestCase
{
    public void testTest()
    {
        AlgorithmFactory af2 = new AlgorithmFactory("jws-algorithms.properties");
    }

    public void testAllJwsKeyTypesNotNull()
    {
        AlgorithmFactoryFactory algoFactoryFactory = AlgorithmFactoryFactory.getInstance();
        AlgorithmFactory<JsonWebSignatureAlgorithm> jwsAlgorithmFactory = algoFactoryFactory.getJwsAlgorithmFactory();

        for (String algo : jwsAlgorithmFactory.getSupportedAlgorithms())
        {
            JsonWebSignatureAlgorithm jsonWebSignatureAlgorithm = jwsAlgorithmFactory.getAlgorithm(algo);
            assertNotNull(jsonWebSignatureAlgorithm.getKeyType());
        }
    }
}
