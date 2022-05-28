package com.fxal.client.cmp.signer;

import com.sun.org.slf4j.internal.Logger;
import com.sun.org.slf4j.internal.LoggerFactory;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.operator.ContentSigner;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.SecureRandom;

/**
 *  @author: caiming
 *  @Date: 2022/5/13 8:56
 *  @Description:
 */


public class GMContentSignerBuilder {

    private static final Logger LOG = LoggerFactory.getLogger(GMContentSignerBuilder.class);


    public ContentSigner build(PrivateKey var1) throws InvalidKeyException {
        final SM2PreprocessSigner signer = new SM2PreprocessSigner();
        CipherParameters cipherParameters = ECUtil.generatePrivateKeyParameter(var1);
        CipherParameters pwr = new ParametersWithRandom(cipherParameters, new SecureRandom());
        signer.init(true, pwr);
        return new ContentSigner() {
            OutputStream outputStream = new ByteArrayOutputStream();

            public AlgorithmIdentifier getAlgorithmIdentifier() {
                return new AlgorithmIdentifier(GMObjectIdentifiers.sm2sign_with_sm3);
            }

            public OutputStream getOutputStream() {
                reset();
                return outputStream;
            }

            public byte[] getSignature() {
                byte[] dataToSign = ((ByteArrayOutputStream) outputStream).toByteArray();
                byte[] eHash1 = signer.preprocess(dataToSign, 0, dataToSign.length);
                byte[] sign1 = new byte[0];
                try {
                    sign1 = signer.generateSignature(eHash1);
                } catch (CryptoException e) {
                    LOG.error(e.getLocalizedMessage());
                }
                return sign1;
            }

            private void reset() {
                ((ByteArrayOutputStream) outputStream).reset();
            }
        };
    }


}
