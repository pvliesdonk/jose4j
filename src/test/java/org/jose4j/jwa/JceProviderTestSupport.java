package org.jose4j.jwa;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

/**
 *
 */
public class JceProviderTestSupport
{
    private static void reinitialize()
    {
        AlgorithmFactoryFactory.getInstance().reinitialize();
    }

    public static void runWithBouncyCastleProvider(RunnableTest test)  throws Exception
    {
        runWithBouncyCastleProvider(test, true);
    }

    public static void runWithBouncyCastleProvider(RunnableTest test, boolean doReinitialize) throws Exception
    {
        BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
        boolean hasBouncyCastleAlready = Security.getProvider(bouncyCastleProvider.getName()) != null;

        try
        {
            if (!hasBouncyCastleAlready)
            {
                Security.addProvider(bouncyCastleProvider);
                if (doReinitialize)
                {
                    reinitialize();
                }
            }

            test.runTest();
        }
        finally
        {
            if (!hasBouncyCastleAlready)
            {
                Security.removeProvider(bouncyCastleProvider.getName());
                if (doReinitialize)
                {
                    reinitialize();
                }
            }
        }
    }

    public static interface RunnableTest
    {
        public abstract void runTest() throws Exception;
    }
}
