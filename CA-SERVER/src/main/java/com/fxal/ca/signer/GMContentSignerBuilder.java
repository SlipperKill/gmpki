package com.fxal.ca.signer;

import com.fxal.ca.common.api.DLL_API;
import com.fxal.ca.common.api.GM0018_API;
import com.fxal.ca.common.exception.CASecurityException;
import com.fxal.ca.util.GMOID;
import com.sun.jna.ptr.PointerByReference;

import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
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

//    public ContentSigner build(int devType, String identity) {
//        return new ContentSigner() {
//            OutputStream outputStream = new ByteArrayOutputStream();
//
//            @Override
//            public AlgorithmIdentifier getAlgorithmIdentifier() {
//                return new AlgorithmIdentifier(GMObjectIdentifiers.sm2sign_with_sm3);
//            }
//
//            @Override
//            public OutputStream getOutputStream() {
//                reset();
//                return outputStream;
//            }
//
//            @Override
//            public byte[] getSignature() {
//                byte[] dataToSign = ((ByteArrayOutputStream) outputStream).toByteArray();
//                try {
//                    PointerByReference phDeviceHandle = GM0018_API.openDevice(devType);
//                    PointerByReference phSessionHandle = GM0018_API.openSession(phDeviceHandle);
//                    byte[] signature = GM0018_API.identitySign(phSessionHandle, identity, dataToSign);
//                    GM0018_API.closeSession(phSessionHandle);
//                    GM0018_API.closeDevice(phDeviceHandle, devType);
//                    return signature;
//                } catch (CASecurityException e) {
//                    LOG.error(e.getLocalizedMessage());
//                    return null;
//                }
//            }
//
//            private void reset() {
//                ((ByteArrayOutputStream) outputStream).reset();
//            }
//        };
//    }

   

    public ContentSigner build(final int keyIndex, final String keyPassword) {
        return new ContentSigner() {
            OutputStream outputStream = new ByteArrayOutputStream();

            public final AlgorithmIdentifier getAlgorithmIdentifier() {
                return new AlgorithmIdentifier(GMObjectIdentifiers.sm2sign_with_sm3);
            }

            public OutputStream getOutputStream() {
                reset();
                return outputStream;
            }

            public byte[] getSignature() {
                try {
                    return getPlainSignature();
                } catch (CASecurityException | IOException e) {
                    LOG.error(e.getLocalizedMessage());
                    return null;
                }
            }

            private byte[] getPlainSignature() throws CASecurityException, IOException {

                byte[] dataToSign = ((ByteArrayOutputStream) outputStream).toByteArray();
                PointerByReference phDeviceHandle = GM0018_API.openDevice();
                PointerByReference phSessionHandle = GM0018_API.openSession(phDeviceHandle);
                DLL_API.PucPublicKey publicKey = GM0018_API.exportSignPublicKey(phSessionHandle, keyIndex);
                GM0018_API.getPrivateKeyAccessRight(phSessionHandle, keyIndex, keyPassword);

                GM0018_API.hashInit(phSessionHandle, GMOID.SGD_SM3, publicKey, new String(Hex.decode("31323334353637383132333435363738")));
                GM0018_API.hashUpdate(phSessionHandle, dataToSign);
                byte[] hash = GM0018_API.hashFinal(phSessionHandle);
                byte[] signature = GM0018_API.internalSignECC(phSessionHandle, keyIndex, hash);
                GM0018_API.releasePrivateKeyAccessRight(phSessionHandle, keyIndex);
                GM0018_API.closeSession(phSessionHandle);
                GM0018_API.closeDevice(phDeviceHandle);
                return signature;
            }

            private void reset() {
                ((ByteArrayOutputStream) outputStream).reset();
            }
        };
    }

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
