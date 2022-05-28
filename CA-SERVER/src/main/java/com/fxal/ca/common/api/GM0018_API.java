package com.fxal.ca.common.api;

import com.fxal.ca.util.Base64;
import com.fxal.ca.common.exception.CASecurityException;
import com.fxal.ca.util.GMOID;
import com.fxal.ca.util.KeyUtil;
import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;

import java.io.IOException;

/**
 * @author caiming
 * @title: PCIE_API
 * @description: TODO
 * @date 2019/5/21 0021上午 10:13
 */
public class GM0018_API {
    public static PointerByReference openDevice() throws CASecurityException {
        PointerByReference phDeviceHandle = new PointerByReference();
        int i = DLL_API.instance.SDF_OpenDevice(phDeviceHandle);
        if (i != 0) {
            throw new CASecurityException("GM0018.SDF_OpenDevice failed: " + i);
        }
        return phDeviceHandle;
    }

    public static void closeDevice(PointerByReference phDeviceHandle) throws CASecurityException {
        int i = DLL_API.instance.SDF_CloseDevice(phDeviceHandle.getValue());
        if (i != 0) {
            throw new CASecurityException("GM0018.closeDevice failed: " + i);
        }
    }

    public static PointerByReference openSession(PointerByReference phDeviceHandle) throws CASecurityException {
        PointerByReference phSessionHandle = new PointerByReference();
        int i = DLL_API.instance.SDF_OpenSession(phDeviceHandle.getValue(), phSessionHandle);
        if (i != 0) {
            throw new CASecurityException("GM0018.SDF_OpenSession failed: " + i);
        }
        return phSessionHandle;
    }

    public static void getPrivateKeyAccessRight(PointerByReference phSessionHandle, int keyIndex, String keyPassword) throws CASecurityException {
        Pointer pucPassword = new Memory(keyPassword.length() + 1);
        pucPassword.setString(0, keyPassword);
        int i = DLL_API.instance.SDF_GetPrivateKeyAccessRight(phSessionHandle.getValue(), keyIndex, pucPassword, keyPassword.length());
        if (i != 0) {
            throw new CASecurityException("GM0018.SDF_GetPrivateKeyAccessRight failed: " + i);
        }
    }

    public static void hashInit(PointerByReference phSessionHandle, int uiAlgID, DLL_API.PucPublicKey pucPublicKey, String userID) throws CASecurityException {
        Pointer pucID = new Memory(userID.length() + 1);
        pucID.setString(0, userID);
        int i = DLL_API.instance.SDF_HashInit(phSessionHandle.getValue(), uiAlgID, pucPublicKey, pucID, userID.length());
        if (i != 0) {
            throw new CASecurityException("GM0018.SDF_HashInit failed: " + i);
        }
    }

    public static void hashUpdate(PointerByReference phSessionHandle, byte[] data) throws CASecurityException {
        Pointer pucData = new Memory(data.length);
        pucData.write(0, data, 0, data.length);
        int i = DLL_API.instance.SDF_HashUpdate(phSessionHandle.getValue(), pucData, data.length);
        if (i != 0) {
            throw new CASecurityException("GM0018.SDF_HashUpdate failed: " + i);
        }
    }

    public static byte[] hashFinal(PointerByReference phSessionHandle) throws CASecurityException {
        Pointer pucHash = new Memory(32);
        IntByReference puiHashLength = new IntByReference();
        int i = DLL_API.instance.SDF_HashFinal(phSessionHandle.getValue(), pucHash, puiHashLength);
        if (i != 0) {
            throw new CASecurityException("GM0018.SDF_HashFinal failed: " + i);
        }
        byte[] hash = new byte[32];
        pucHash.read(0, hash, 0, puiHashLength.getValue());
        return hash;
    }

    public static byte[] internalSignECC(PointerByReference phSessionHandle, int keyIndex, byte[] hash) throws CASecurityException, IOException {
        DLL_API.ECCSignature.ByReference pucSignature = new DLL_API.ECCSignature.ByReference();
        Pointer pucData = new Memory(32);
        pucData.write(0, hash, 0, hash.length);
        int i = DLL_API.instance.SDF_InternalSign_ECC(phSessionHandle.getValue(), keyIndex, pucData, hash.length, pucSignature);
        if (i != 0) {
            throw new CASecurityException("GM0018.SDF_InternalSign_ECC failed: " + i);
        }
        return KeyUtil.covertSignature(pucSignature);
    }

    public static int externalVerify_ECC(PointerByReference phSessionHandle, int uiAlgID,
                                         DLL_API.PucPublicKey pucPublicKey, byte[] hash,
                                         DLL_API.ECCSignature pucSignature) {
        Pointer pucData = new Memory(32);
        pucData.write(0, hash, 0, hash.length);
        int i = DLL_API.instance.SDF_ExternalVerify_ECC(phSessionHandle.getValue(), uiAlgID, pucPublicKey, pucData, 32, pucSignature);
        return i;
    }

    public static void releasePrivateKeyAccessRight(PointerByReference phSessionHandle, int keyIndex) throws CASecurityException {
        int i = DLL_API.instance.SDF_ReleasePrivateKeyAccessRight(phSessionHandle.getValue(), keyIndex);
        if (i != 0) {
            throw new CASecurityException("GM0018.SDF_ReleasePrivateKeyAccessRight failed: " + i);
        }
    }

    public static void closeSession(PointerByReference phSessionHandle) throws CASecurityException {
        int i = DLL_API.instance.SDF_CloseSession(phSessionHandle.getValue());
        if (i != 0) {
            throw new CASecurityException("GM0018.SDF_CloseSession failed: " + i);
        }
    }

    public static DLL_API.PucPublicKey genMasterKey(PointerByReference phSessionHandle) throws CASecurityException {
        DLL_API.PucPublicKey.ByReference pucPublicKey = new DLL_API.PucPublicKey.ByReference();
        int i = DLL_API.instance.ServIBK_GenMasterKey(phSessionHandle.getValue(), pucPublicKey);
        if (i != 0) {
            throw new CASecurityException("GM0018.ServIBK_GenMasterKey failed: " + i);
        }
        return pucPublicKey;
    }

    public static DLL_API.PucPublicKey exportMasterKey(PointerByReference phSessionHandle) throws CASecurityException {
        DLL_API.PucPublicKey.ByReference pucPublicKey = new DLL_API.PucPublicKey.ByReference();
        int i = DLL_API.instance.ServIBK_ExportMasterKey(phSessionHandle.getValue(), pucPublicKey);
        if (i != 0) {
            throw new CASecurityException("GM0018.ServIBK_ExportMasterKey failed: " + i);
        }
        return pucPublicKey;

    }

    public static DLL_API.EnvelopedKeyBlob calculateECCKeyPair(PointerByReference phSessionHandle, String identity, Long notBefore, Long notAfter, DLL_API.PucPublicKey pucPublicKey) throws CASecurityException {
        Pointer identityPointer = new Memory(identity.length() + 1);
        identityPointer.setString(0, identity);
        DLL_API.EnvelopedKeyBlob.ByReference pEncrypt = new DLL_API.EnvelopedKeyBlob.ByReference();
        int i;
        if (notBefore != null && notAfter != null) {
            Pointer notBeforePointer = new Memory(8);
            notBeforePointer.setLong(0, notBefore);
            Pointer notAfterPointer = new Memory(8);
            notAfterPointer.setLong(0, notAfter);
            i = DLL_API.instance.ServIBK_CalculateECCKeyPair(phSessionHandle.getValue(), identityPointer, identity.length(),
                    notAfterPointer, 8, notAfterPointer, 8,
                    pucPublicKey, pEncrypt);
        } else {
            i = DLL_API.instance.ServIBK_CalculateECCKeyPair(phSessionHandle.getValue(), identityPointer, identity.length(),
                    null, 0, null, 0,
                    pucPublicKey, pEncrypt);
        }
        if (i != 0) {
            throw new CASecurityException("GM0018.calculateECCKeyPair failed: " + i);
        }

        return pEncrypt;
    }








    public static DLL_API.PucPublicKey genECCKeyPair(PointerByReference phSessionHandle, int keyIndex) throws CASecurityException {
        DLL_API.PucPublicKey.ByReference pucPublicKey = new DLL_API.PucPublicKey.ByReference();
        int i = DLL_API.instance.ServIBK_GenECCKeyPair(phSessionHandle.getValue(), keyIndex, 256, pucPublicKey);
        if (i != 0) {
            throw new CASecurityException("GM0018.genECCKeyPair failed: " + i);
        }
        return pucPublicKey;
    }

    public static DLL_API.PucPublicKey genTempECCKeyPair(PointerByReference phSessionHandle, int keyIndex) throws CASecurityException {
        DLL_API.PucPublicKey.ByReference pucPublicKey = new DLL_API.PucPublicKey.ByReference();
        int i = DLL_API.instance.ServIBK_GenTempECCKeyPair(phSessionHandle.getValue(), keyIndex, 256, pucPublicKey);
        if (i != 0) {
            throw new CASecurityException("GM0018.genTempECCKeyPair failed: " + i);
        }
        return pucPublicKey;
    }

    public static void importECCKeyPair(PointerByReference phSessionHandle, int keyIndex, DLL_API.EnvelopedKeyBlob cipher) throws CASecurityException {
        int i = DLL_API.instance.ServIBK_ImportECCKeyPair(phSessionHandle.getValue(), keyIndex, cipher);
        if (i != 0) {
            throw new CASecurityException("GM0018.importECCKeyPair failed: " + i);
        }
    }

    public static PointerByReference importKeyWithISK_ECC(PointerByReference phSessionHandle, int keyIndex, DLL_API.ECCCipher pucKey) throws CASecurityException {
        PointerByReference phKeyHandle = new PointerByReference();
        int i = DLL_API.instance.SDF_ImportKeyWithISK_ECC(phSessionHandle.getValue(), keyIndex, pucKey, phKeyHandle);
        if (i != 0) {
            throw new CASecurityException("GM0018.importECCKeyPair failed: " + i);
        }
        return phKeyHandle;
    }

    public static void deCryptInit(PointerByReference phSessionHandle, PointerByReference phKeyHandle) throws CASecurityException {
        int[] IV = new int[]{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
        Pointer pucIV = new Pointer(IV.length);
        pucIV.write(0, IV, 0, IV.length);
        int i = DLL_API.instance.SDF_DeCryptInit(phSessionHandle.getValue(), phKeyHandle.getValue(), GMOID.SGD_SM4_CBC, pucIV, IV.length);
        if (i != 0) {
            throw new CASecurityException("GM0018.deCryptInit failed: " + i);
        }
    }

    public static String decryptUpdate(PointerByReference phSessionHandle, PointerByReference phKeyHandle, String encData) throws CASecurityException {
        Pointer pucEncData = new Pointer(encData.length());
        pucEncData.setString(0, encData);
        Pointer pucData = new Pointer(encData.length());
        IntByReference puiDataLength = new IntByReference();
        int i = DLL_API.instance.SDF_DecryptUpdate(phSessionHandle.getValue(), phKeyHandle.getValue(), pucEncData, encData.length(), pucData, puiDataLength);
        if (i != 0) {
            throw new CASecurityException("GM0018.decryptUpdate failed: " + i);
        }
        return pucData.getString(0);
    }

    public static void decryptFinal(PointerByReference phSessionHandle, PointerByReference phKeyHandle) throws CASecurityException {
        int i = DLL_API.instance.SDF_DecryptFinal(phSessionHandle.getValue(), phKeyHandle.getValue());
        if (i != 0) {
            throw new CASecurityException("GM0018.decryptFinal failed: " + i);
        }
    }

    public static byte[] decrypt(PointerByReference phSessionHandle, PointerByReference phKeyHandle, String encData) throws CASecurityException {
        byte[] IV = new byte[]{0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef, (byte) 0xfe, (byte) 0xdc, (byte) 0xba, (byte) 0x98, 0x76, 0x54, 0x32, 0x10};
        Pointer pucIV = new Memory(IV.length);
        pucIV.write(0, IV, 0, IV.length);
        byte[] cipher = Base64.decode(encData);
        Pointer pucEncData = new Memory(cipher.length + 1);
        pucEncData.write(0, cipher, 0, cipher.length);
        Pointer pucData = new Memory(cipher.length + 1);
        IntByReference puiDataLength = new IntByReference();
        int i = DLL_API.instance.SDF_Decrypt(phSessionHandle.getValue(), phKeyHandle.getValue(), GMOID.SGD_SM4_CBC, pucIV, pucEncData, cipher.length, pucData, puiDataLength);
        if (i != 0) {
            throw new CASecurityException("GM0018.decrypt failed: " + i);
        }
        byte[] data = new byte[puiDataLength.getValue()];
        pucData.read(0, data, 0, puiDataLength.getValue());
        return data;
    }

    public static void importMasterKey(PointerByReference phSessionHandle, DLL_API.PucPublicKey pucPublicKey) throws CASecurityException {
        int i = DLL_API.instance.ServIBK_ImportMasterKey(phSessionHandle.getValue(), pucPublicKey);
        if (i != 0) {
            throw new CASecurityException("GM0018.decrypt failed: " + i);
        }
    }

    public static DLL_API.PucPublicKey exportSignPublicKey(PointerByReference phSessionHandle, int keyIndex) throws CASecurityException {
        DLL_API.PucPublicKey.ByReference pucPublicKey = new DLL_API.PucPublicKey.ByReference();
        int i = DLL_API.instance.SDF_ExportSignPublicKey_ECC(phSessionHandle.getValue(), keyIndex, pucPublicKey);
        if (i != 0) {
            throw new CASecurityException("GM0018.exportSignPublicKey failed: " + i);
        }
        return pucPublicKey;
    }

    public static DLL_API.PucPublicKey exportEncPublicKey(PointerByReference phSessionHandle, int keyIndex) throws CASecurityException {
        DLL_API.PucPublicKey.ByReference pucPublicKey = new DLL_API.PucPublicKey.ByReference();
        int i = DLL_API.instance.SDF_ExportEncPublicKey_ECC(phSessionHandle.getValue(), keyIndex, pucPublicKey);
        if (i != 0) {
            throw new CASecurityException("GM0018.exportEncPublicKey failed: " + i);
        }
        return pucPublicKey;
    }

    public static void devInit(PointerByReference phSessionHandle, int type) throws CASecurityException {
        int i = DLL_API.instance.SDF_DevInit(phSessionHandle.getValue(), type);
        if (i != 0) {
            throw new CASecurityException("GM0018.SDF_DevInit failed: " + i);
        }
    }

    /**
     * <p>Title: changePin</p>
     * <p>Description:修改设备pin码</p>
     *
     * @param phSessionHandle
     * @param type
     * @param oldPin
     * @param newPin
     * @throws CASecurityException
     */
    public static void changePin(PointerByReference phSessionHandle, int type, String oldPin, String newPin) throws CASecurityException {
        int i = DLL_API.instance.SDF_ChangePin(phSessionHandle.getValue(), type, oldPin, newPin);
        if (i != 0) {
            throw new CASecurityException("GM0018.changePin failed: " + i);
        }
    }

    /**
     * <p>Title: verifyPin</p>
     * <p>Description:验证设备pin码 </p>
     *
     * @param phSessionHandle
     * @param type
     * @param pinLen
     * @param pin
     * @throws CASecurityException
     */
    public static void verifyPin(PointerByReference phSessionHandle, int type, int pinLen, String pin) throws CASecurityException {
        int i = DLL_API.instance.SDF_VerifyPin(phSessionHandle.getValue(), type, pinLen, pin);
        if (i != 0) {
            throw new CASecurityException("GM0018.SDF_VerifyPin failed: " + i);
        }
    }

    public static void segMentKeyThreshold(PointerByReference phSessionHandle, int sgmNum, int recoverNum, int type, int keyIndex) throws CASecurityException {
        int i = DLL_API.instance.SDF_SegMentKeyThreshold(phSessionHandle.getValue(), sgmNum, recoverNum, type, keyIndex);
        if (i != 0) {
            throw new CASecurityException("GM0018.SegMentKeyThreshold failed: " + i);
        }
    }

    public static byte[] getSegMentKeyThreshold(PointerByReference phSessionHandle, int index, String pin, int nPinLen) throws CASecurityException {

        Pointer SegKey = new Memory(4096);
        IntByReference SegKeyLen = new IntByReference();
        int tag = DLL_API.instance.SDF_GetSegMentKeyThreshold(phSessionHandle.getValue(), index, pin, nPinLen, SegKey, SegKeyLen);
        if (tag != 0) {
            throw new CASecurityException("GM0018.getSegMentKeyThreshold failed: " + tag);
        }
        return SegKey.getByteArray(0, SegKeyLen.getValue());
    }

    /**
     * <p>Title: keyRecoveryInitThreshold</p>
     * <p>Description: 初始化备份数据的恢复操作 </p>
     *
     * @param phSessionHandle
     * @param sgmNum
     * @param recoverNum
     * @param type
     * @param keyIndex
     * @throws CASecurityException
     */
    public static void keyRecoveryInitThreshold(PointerByReference phSessionHandle, int sgmNum, int recoverNum, int type, int keyIndex) throws CASecurityException {
        int i = DLL_API.instance.SDF_KeyRecoveryInitThreshold(phSessionHandle.getValue(), sgmNum, recoverNum, type, keyIndex);
        if (i != 0) {
            throw new CASecurityException("GM0018.keyRecoveryInitThreshold failed: " + i);
        }
    }

    /**
     * <p>Title: importSegmentKeyThreshold</p>
     * <p>Description:导入单份备份数据 </p>
     *
     * @param index     备份数据索引
     * @param pin       PIN码
     * @param PINLen    PIN码长度
     * @param Cipher    对称密钥分割后的数据
     * @param SegKeyLen 分割的数据长度
     * @throws CASecurityException
     */
    public static void importSegmentKeyThreshold(PointerByReference phSessionHandle, int index, String pin, int PINLen, Pointer Cipher, int SegKeyLen) throws CASecurityException {
        int i = DLL_API.instance.SDF_ImportSegmentKeyThreshold(phSessionHandle.getValue(), index, pin, PINLen, Cipher, SegKeyLen);
        if (i != 0) {
            throw new CASecurityException("GM0018.importSegmentKeyThreshold failed: " + i);
        }
    }

    /**
     * <p>Title: keyRecoveryFinishThreshold</p>
     * <p>Description:恢复密钥数据  </p>
     *
     * @param phSessionHandle
     * @throws CASecurityException
     */
    public static void keyRecoveryFinishThreshold(PointerByReference phSessionHandle) throws CASecurityException {
        int i = DLL_API.instance.SDF_KeyRecoveryFinishThreshold(phSessionHandle.getValue());
        if (i != 0) {
            throw new CASecurityException("GM0018.keyRecoveryFinishThreshold failed: " + i);
        }
    }
}
