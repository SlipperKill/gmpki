package com.fxal.ca.signer;

import com.fxal.ca.common.api.DLL_API;
import com.fxal.ca.common.api.GM0018_API;
import com.fxal.ca.common.exception.CASecurityException;
import com.fxal.ca.util.GMOID;
import com.fxal.ca.util.KeyUtil;
import com.sun.jna.ptr.PointerByReference;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.io.IOException;
import java.math.BigInteger;

/**
 * @author caiming
 * @title: SM2Signer
 * @projectName ibk-kgc
 * @description: TODO
 * @date 2019/6/4 0004上午 10:54
 */
public class SM2ContentVerifySigner implements Closeable {

    Logger logger = LoggerFactory.getLogger(SM2ContentVerifySigner.class);

    private SubjectPublicKeyInfo publicKey;

    private PointerByReference phSessionHandle;
    private PointerByReference phDeviceHandle;
    private final int devType;

    public SM2ContentVerifySigner(int devType) {
        this.devType = devType;
        try {
            phDeviceHandle = GM0018_API.openDevice();
            phSessionHandle = GM0018_API.openSession(phDeviceHandle);
        } catch (CASecurityException ex) {
            logger.error("SM2ContentSigner init failed = " + ex.getMessage());
        }
    }


    public void engineInitVerify(SubjectPublicKeyInfo publicKey, byte[] data) {
        try {
            this.publicKey = publicKey;
            DLL_API.PucPublicKey pucPublicKey = KeyUtil.convertPublicKey(this.publicKey);
            GM0018_API.hashInit(phSessionHandle, GMOID.SGD_SM3, pucPublicKey, "1234567812345678");
            GM0018_API.hashUpdate(phSessionHandle, data);
        } catch (CASecurityException | IOException ex) {
            logger.error("SM2ContentSigner engineInitVerify faild = " + ex.getMessage());
        }
    }

    public boolean engineVerify(byte[] eccSignature) {
        try {
            byte[] hash = GM0018_API.hashFinal(phSessionHandle);
            DLL_API.PucPublicKey pucPublicKey = KeyUtil.convertPublicKey(this.publicKey);
            DLL_API.ECCSignature signature = new DLL_API.ECCSignature();
            BigInteger[] rs = derDecode(eccSignature);
            System.arraycopy(toByteArray(rs[0]), 0, signature.r, 0, 32);
            System.arraycopy(toByteArray(rs[1]), 0, signature.s, 0, 32);
            int result = GM0018_API.externalVerify_ECC(phSessionHandle, GMOID.SGD_SM2, pucPublicKey, hash, signature);
            if (result != 0) {
                return false;
            }
        } catch (CASecurityException | IOException ex) {
            logger.error("SM2ContentSigner engineVerify faild = " + ex.getMessage());
            return false;
        }
        return true;
    }

    public void close() {
        try {
            GM0018_API.closeSession(phSessionHandle);
            GM0018_API.closeDevice(phDeviceHandle);
        } catch (CASecurityException ex) {
            logger.error("SM2ContentSigner close faild = " + ex.getMessage());
        }
    }

    private BigInteger[] derDecode(byte[] encoding)
            throws IOException {
        ASN1Sequence seq = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(encoding));
        if (seq.size() != 2) {
            return null;
        }

        BigInteger r = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();
        BigInteger s = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue();

        byte[] expectedEncoding = derEncode(r, s);
        if (!Arrays.constantTimeAreEqual(expectedEncoding, encoding)) {
            return null;
        }

        return new BigInteger[]{r, s};
    }

    private byte[] derEncode(BigInteger r, BigInteger s)
            throws IOException {

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));
        return new DERSequence(v).getEncoded(ASN1Encoding.DER);
    }

    private static byte[] toByteArray(BigInteger bi) {
        byte[] array = bi.toByteArray();
        if (array[0] == 0 && array.length > 32) {
            byte[] tmp = new byte[array.length - 1];
            System.arraycopy(array, 1, tmp, 0, tmp.length);
            array = tmp;
        }
        if(array.length<32){
            byte[] tmp = new byte[32];
            System.arraycopy(array,0,tmp,tmp.length-array.length,array.length);
            array = tmp;
        }
        return array;
    }
}
