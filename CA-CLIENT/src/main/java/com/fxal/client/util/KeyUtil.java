package com.fxal.client.util;


import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;

import java.io.IOException;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import static com.fxal.client.util.Args.notNull;

/**
 * @author caiming
 * @title: KeyUtil
 * @projectName ibk-basic
 * @description: TODO
 * @date 2019/6/5 0005下午 5:28
 */
public class KeyUtil {
    public static final ASN1ObjectIdentifier ID_SM2_PUBKEY_PARAM = new ASN1ObjectIdentifier("1.2.156.10197.1.301");


    private static final Map<String, KeyFactory> KEY_FACTORIES = new HashMap<>();


    public static PublicKey generatePublicKey(SubjectPublicKeyInfo pkInfo)
            throws InvalidKeySpecException {
        notNull(pkInfo, "pkInfo");

        X509EncodedKeySpec keyspec;
        try {
            keyspec = new X509EncodedKeySpec(pkInfo.getEncoded());
        } catch (IOException ex) {
            throw new InvalidKeySpecException(ex.getMessage(), ex);
        }
        ASN1ObjectIdentifier aid = pkInfo.getAlgorithm().getAlgorithm();

        String algorithm = null;
        if (PKCSObjectIdentifiers.rsaEncryption.equals(aid)) {
            algorithm = "RSA";
        } else if (X9ObjectIdentifiers.id_dsa.equals(aid)) {
            algorithm = "DSA";
        } else if (X9ObjectIdentifiers.id_ecPublicKey.equals(aid)) {
            algorithm = "EC";
        }

        if (algorithm == null) {
            throw new InvalidKeySpecException("unsupported key algorithm: " + aid);
        }

        KeyFactory kf = getKeyFactory(algorithm);
        synchronized (kf) {
            return kf.generatePublic(keyspec);
        }
    }

    private static KeyFactory getKeyFactory(String algorithm) throws InvalidKeySpecException {
        String alg = algorithm.toUpperCase();
        if ("ECDSA".equals(alg)) {
            alg = "EC";
        }
        synchronized (KEY_FACTORIES) {
            KeyFactory kf = KEY_FACTORIES.get(algorithm);
            if (kf != null) {
                return kf;
            }

            try {
                kf = KeyFactory.getInstance(algorithm, "BC");
            } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
                throw new InvalidKeySpecException("could not find KeyFactory for " + algorithm
                        + ": " + ex.getMessage());
            }
            KEY_FACTORIES.put(algorithm, kf);
            return kf;
        }
    }

    public static AsymmetricKeyParameter generatePublicKeyParameter(PublicKey key)
            throws InvalidKeyException {
        notNull(key, "key");
        if (key instanceof ECPublicKey) {
            return ECUtil.generatePublicKeyParameter(key);
        } else {
            throw new InvalidKeyException("unknown key " + key.getClass().getName());
        }
    } // method generatePublicKeyParameter

}
