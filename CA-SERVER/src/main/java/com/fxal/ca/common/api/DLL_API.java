package com.fxal.ca.common.api;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;

import java.util.ArrayList;
import java.util.List;

/**
 * @author caiming
 * @title: DLL_API
 * @projectName ibk-CA
 * @description: TODO
 * @date 2019/5/16 0016下午 7:40
 */
public interface DLL_API extends Library {

	DLL_API instance = Native.loadLibrary("D:\\libGMT0018", DLL_API.class);
	//DLL_API instance = Native.loadLibrary("GMT0018", DLL_API.class);


    class PucPublicKey extends Structure {
        public static class ByReference extends PucPublicKey implements Structure.ByReference {
        }

        public static class ByValue extends PucPublicKey implements Structure.ByValue {
        }

        public int bits = 0;
        public byte[] x = new byte[64];
        public byte[] y = new byte[64];

        @Override
        protected List<String> getFieldOrder() {
            List<String> Field = new ArrayList<String>();
            Field.add("bits");
            Field.add("x");
            Field.add("y");

            return Field;
        }
    }

    class PucPrivateKey extends Structure {
        public static class ByReference extends PucPrivateKey implements Structure.ByReference {
        }

        public static class ByValue extends PucPublicKey implements Structure.ByValue {
        }

        public int bits = 0;
        public byte[] K = new byte[64];

        @Override
        protected List<String> getFieldOrder() {
            List<String> Field = new ArrayList<String>();
            Field.add("bits");
            Field.add("K");

            return Field;
        }
    }

    class ECCSignature extends Structure {

        public static class ByReference extends ECCSignature implements Structure.ByReference {
        }

        public static class ByValue extends ECCSignature implements Structure.ByValue {
        }

        public byte[] r = new byte[64];
        public byte[] s = new byte[64];

        @Override
        protected List<String> getFieldOrder() {
            List<String> Field = new ArrayList<String>();
            Field.add("r");
            Field.add("s");
            return Field;
        }
    }

    class ECCCipher extends Structure {
        @Override
        protected List<String> getFieldOrder() {
            List<String> Field = new ArrayList<String>();
            Field.add("x");
            Field.add("y");
            Field.add("M");
            Field.add("L");
            Field.add("C");
            return Field;
        }

        public static class ByReference extends ECCCipher implements Structure.ByReference {
        }

        public static class ByValue extends ECCCipher implements Structure.ByValue {
        }

        public byte[] x = new byte[64];
        public byte[] y = new byte[64];
        public byte[] M = new byte[32];
        public int L = 0;
        public byte[] C = new byte[16];
    }

    class EnvelopedKeyBlob extends Structure {
        @Override
        protected List<String> getFieldOrder() {
            List<String> Field = new ArrayList<String>();
            Field.add("ulAsymmAlgID");
            Field.add("ulSymmAlgID");
            Field.add("PubKey");
            Field.add("cbEncryptedPriKey");
            Field.add("ECCCipherBlob");
            return Field;
        }

        public static class ByReference extends EnvelopedKeyBlob implements Structure.ByReference {
        }

        public static class ByValue extends EnvelopedKeyBlob implements Structure.ByValue {
        }

        public int ulAsymmAlgID = 0;
        public int ulSymmAlgID = 0;
        public PucPublicKey PubKey = new PucPublicKey();
        public byte[] cbEncryptedPriKey = new byte[64];
        public ECCCipher ECCCipherBlob = new ECCCipher();

    }

    //设备类接口
    int SDF_OpenDevice(PointerByReference phDeviceHandle);

    int SDF_CloseDevice(Pointer phDeviceHandle);

    int SDF_OpenSession(Pointer phDeviceHandle, PointerByReference phSessionHandle);

    int SDF_CloseSession(Pointer phSessionHandle);

    int SDF_GetPrivateKeyAccessRight(Pointer phSessionHandle, int uiKeyIndex, Pointer pucPassword, int uiPwdLength);

    int SDF_ReleasePrivateKeyAccessRight(Pointer phSessionHandle, int uiKeyIndex);


    //密钥管理类接口
    int SDF_ExportSignPublicKey_ECC(Pointer phSessionHandle, int keyIndex, PucPublicKey.ByReference pucPublicKey);

    int SDF_ExportEncPublicKey_ECC(Pointer phSessionHandle, int keyIndex, PucPublicKey.ByReference pucPublicKey);

    //hash类接口
    int SDF_HashInit(Pointer phSessionHandle, int uiAlgID, PucPublicKey pucPublicKey, Pointer pucID, int uiIDLength);

    int SDF_HashUpdate(Pointer phSessionHandle, Pointer pucData, int uiDataLength);

    int SDF_HashFinal(Pointer phSessionHandle, Pointer pucHash, IntByReference puiHashLength);

    //签名验签
    int SDF_InternalSign_ECC(Pointer phSessionHandle, int uiISKIndex, Pointer pucData, int uiDataLength, ECCSignature.ByReference pucSignature);

    int SDF_InternalVerify_ECC(Pointer phSessionHandle, int uiISKIndex, Pointer pucData, int uiDataLength, ECCSignature.ByReference pucSignature);

    int SDF_ExternalVerify_ECC(Pointer phSessionHandle, int uiAlgID, PucPublicKey pucPublicKey, Pointer pucDataInput, int uiInputLength, ECCSignature pucSignature);

    int SDF_ImportKeyWithISK_ECC(Pointer phSessionHandle, int uiISKIndex, ECCCipher pucKey, PointerByReference phKeyHandle);

    //加密解密mac类接口
    int SDF_DeCryptInit(Pointer phSessionHandle, Pointer phKeyHandle, int uiAlgID, Pointer pucIV, int ivLen);

    int SDF_DecryptUpdate(Pointer phSessionHandle, Pointer phKeyHandle, Pointer pucEncData, int uiEncDataLength, Pointer pucData, IntByReference puiDataLength);

    int SDF_DecryptFinal(Pointer phSessionHandle, Pointer phKeyHandle);

    int SDF_Decrypt(Pointer phSessionHandle, Pointer phKeyHandle, int uiAlgID, Pointer pucIV, Pointer pucEncData, int uiEncDataLength, Pointer pucData, IntByReference puiDataLength);

    /* IBK专用接口 */
    /* KGC专用接口*/

    int ServIBK_GenMasterKey(Pointer phSessionHandle, PucPublicKey.ByReference pucPublicKey);

    int ServIBK_CalculateECCKeyPair(Pointer phSessionHandle, Pointer identify, int identifyLen,
                                    Pointer takeEffectDate, int takeEffectDateLen, Pointer loseEffectDate, int loseEffectDateLen,
                                    PucPublicKey pucPublicKey, EnvelopedKeyBlob.ByReference pEncrypt);

    int ServIBK_GenerateKeyPair_ECC(Pointer phSessionHandle, Pointer identify, int identifyLen,
                                    Pointer takeEffectDate, int takeEffectDateLen, Pointer loseEffectDate, int loseEffectDateLen,
                                    PucPublicKey.ByReference pucPublicKey, PucPrivateKey.ByReference pucPrivateKey);

    int ServIBK_GenTempECCKeyPair(Pointer phSessionHandle, int uiKeyIndex, int uiBitLen, PucPublicKey.ByReference pucPublicKey);

    int ServIBK_SignForTI(Pointer phSessionHandle, Pointer identify, int identifyLen,
                          Pointer signId, int signIdLen, Pointer pucData, int uiDataLength,
                          ECCSignature.ByReference pucSignature);

    int ServIBK_SignForTIWithMasterKey(Pointer phSessionHandle, Pointer signId, int signIdLen, Pointer pucData, int uiDataLength,
                                       ECCSignature.ByReference pucSignature);


    int ServIBK_CalculatePubKeyWithIdentity(Pointer phSessionHandle, Pointer identify, int identifyLen, PucPublicKey.ByReference pucPublicKey);

    int ServIBK_GenECCKeyPair(Pointer phSessionHandle, int uiKeyIndex, int uiBitLen, PucPublicKey.ByReference pucPublicKey);

    int ServIBK_ImportECCKeyPair(Pointer phSessionHandle, int uiKeyIndex, EnvelopedKeyBlob cipher);

    int ServIBK_ImportMasterKey(Pointer phSessionHandle, PucPublicKey pucPublicKey);

    int ServIBK_ExportMasterKey(Pointer phSessionHandle, PucPublicKey.ByReference pucPublicKey);

    /**
     * <p>Title: SDF_DevInit</p>
     * <p>Description: 设备初始化</p>
     *
     * @param phSessionHandle
     * @param type
     * @return
     */
    int SDF_DevInit(Pointer phSessionHandle, int type);

    /**
     * <p>Title: SDF_VerifyPin</p>
     * <p>Description:校验PIN码   type:0表示设备PIN </p>
     *
     * @param phSessionHandle
     * @param type            0表示设备PIN
     * @param pinLen
     * @param pin
     * @return
     */
    int SDF_VerifyPin(Pointer phSessionHandle, int type, int pinLen, String pin);

    /**
     * <p>Title: SDF_SegMentKeyThreshold</p>
     * <p>Description:启动密钥分割 </p>
     *
     * @param phSessionHandle 与设备建立的会话句柄
     * @param sgmNum          密钥分割的份数
     * @param recoverNum      密钥恢复时需要的份数
     * @param type            0:单秘钥 1：全秘钥
     * @param keyIndex        单密钥索引。type为0时有效
     * @return
     */
    int SDF_SegMentKeyThreshold(Pointer phSessionHandle, int sgmNum, int recoverNum, int type, int keyIndex);


    /**
     * <p>Title: SDF_GetSegMentKeyThreshold</p>
     * <p>Description: 密钥分割导出</p>
     *
     * @param phSessionHandle 与设备建立的会话句柄
     * @param index           备份数据索引
     * @param pin             PIN码
     * @param nPinLen         PIN码长度
     * @param SegKey          对称密钥分割后的数据（一份）
     * @param SegKeyLen       分割的数据长度
     * @return
     */
    int SDF_GetSegMentKeyThreshold(Pointer phSessionHandle, int index, String pin, int nPinLen, Pointer SegKey, IntByReference SegKeyLen);

    /**
     * <p>Title: SDF_KeyRecoveryInitThreshold</p>
     * <p>Description:初始化备份数据的恢复操作 </p>
     *
     * @param phSessionHandle 与设备建立的会话句柄
     * @param sgmNum          密钥分割的份数
     * @param recoverNum      密钥恢复时需要的份数
     * @param type            0:单秘钥 1：全秘钥
     * @param keyIndex        单密钥索引。type为0时有效
     * @return
     */
    int SDF_KeyRecoveryInitThreshold(Pointer phSessionHandle, int sgmNum, int recoverNum, int type, int keyIndex);


    /**
     * <p>Title: SDF_ImportSegmentKeyThreshold</p>
     * <p>Description:导入单份备份数据 </p>
     *
     * @param phSessionHandle 与设备建立的会话句柄
     * @param index           备份数据索引
     * @param pin             PIN码
     * @param PINLen          PIN码长度
     * @param Cipher          对称密钥分割后的数据
     * @param SegKeyLen       分割的数据长度
     * @return
     */
    int SDF_ImportSegmentKeyThreshold(Pointer phSessionHandle, int index, String pin, int PINLen, Pointer Cipher, int SegKeyLen);

    /**
     * <p>Title: SDF_KeyRecoveryFinishThreshold</p>
     * <p>Description:恢复密钥数据 </p>
     *
     * @param phSessionHandle
     * @return
     */
    int SDF_KeyRecoveryFinishThreshold(Pointer phSessionHandle);


    /**
     * <p>Title: SDF_ChangePin</p>
     * <p>Description:修改设备pin码 </p>
     * @param phSessionHandle
     * @param type
     * @param oldPin
     * @param newPin
     * @return
     */
    int SDF_ChangePin(Pointer phSessionHandle, int type, String oldPin, String newPin);
}
