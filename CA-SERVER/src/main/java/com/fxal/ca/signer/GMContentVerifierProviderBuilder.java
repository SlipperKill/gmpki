
package com.fxal.ca.signer;

import com.fxal.ca.protocol.GMObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcECContentVerifierProviderBuilder;

import java.security.NoSuchAlgorithmException;

/**
 *  @author: caiming
 *  @Date: 2022/5/10 10:01
 *  @Description:
 */

// CHECKSTYLE:SKIP
public class GMContentVerifierProviderBuilder extends BcECContentVerifierProviderBuilder {

    private static final DigestAlgorithmIdentifierFinder digestAlgorithmFinder
            = new DefaultDigestAlgorithmIdentifierFinder();

    public GMContentVerifierProviderBuilder() {
        super(digestAlgorithmFinder);
    }

    @Override
    protected Signer createSigner(AlgorithmIdentifier var1) throws OperatorCreationException {
        if(!var1.getAlgorithm().equals(GMObjectIdentifiers.sm2_with_sm3)){
            throw new OperatorCreationException(new NoSuchAlgorithmException().getLocalizedMessage());
        }
        return new SM2Signer();
    } // method createSigner

}
