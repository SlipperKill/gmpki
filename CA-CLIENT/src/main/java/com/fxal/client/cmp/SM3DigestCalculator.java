package com.fxal.client.cmp;

import com.fxal.client.constants.GMObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DigestCalculator;

import java.io.OutputStream;

/**
 * @author: caiming
 * @Date: 2022/5/25 15:55
 * @Description:
 */
public class SM3DigestCalculator implements DigestCalculator {
    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return new AlgorithmIdentifier(GMObjectIdentifiers.sm_3);
    }

    @Override
    public OutputStream getOutputStream() {
        return null;
    }

    @Override
    public byte[] getDigest() {
        return new byte[0];
    }
}
