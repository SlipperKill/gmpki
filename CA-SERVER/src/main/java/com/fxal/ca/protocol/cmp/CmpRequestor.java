package com.fxal.ca.protocol.cmp;

import lombok.Data;
import lombok.ToString;
import org.bouncycastle.asn1.x500.X500Name;

import java.security.cert.X509Certificate;

/**
 * @author: caiming
 * @Date: 2022/4/21 10:28
 * @Description:
 */
@Data
@ToString
public class CmpRequestor {

    private X509Certificate cert;

    private X500Name x500Name;

    private boolean isRa;
}
