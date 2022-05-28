package com.fxal.ca.common.pojo;

import lombok.Data;
import org.bouncycastle.asn1.crmf.EncryptedValue;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

/**
 * @author: caiming
 * @Date: 2022/5/23 16:12
 * @Description:
 */
@Data
public class ApplyKeyResult {

    private Long certNo;

    private SubjectPublicKeyInfo publicKeyInfo;

    private EncryptedValue encryptedValue;
}
