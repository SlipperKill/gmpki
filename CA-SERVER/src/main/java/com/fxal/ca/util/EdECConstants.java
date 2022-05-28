
package com.fxal.ca.util;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class EdECConstants {

  private static final ASN1ObjectIdentifier id_edwards_curve_algs =
      new ASN1ObjectIdentifier("1.3.101");

  public static final ASN1ObjectIdentifier id_X25519 =
      id_edwards_curve_algs.branch("110").intern();
  public static final ASN1ObjectIdentifier id_X448 =
      id_edwards_curve_algs.branch("111").intern();
  public static final ASN1ObjectIdentifier id_Ed25519 =
      id_edwards_curve_algs.branch("112").intern();
  public static final ASN1ObjectIdentifier id_Ed448 =
      id_edwards_curve_algs.branch("113").intern();

  public static final String ALG_X25519 = "X25519";

  public static final String ALG_Ed25519 = "Ed25519";

  public static final String ALG_X448 = "X448";

  public static final String ALG_Ed448 = "Ed448";

  public static final String curve25519 = "curve25519";

  public static final String edwards25519 = "edwards25519";

  public static final String curve448 = "curve448";

  public static final String edwards448 = "edwards448";

  private EdECConstants() {
  }

  public static boolean isEdwardsCurve(String curveName) {
    return edwards25519.equalsIgnoreCase(curveName) || edwards448.equalsIgnoreCase(curveName);
  }

  public static boolean isMontgemoryCurve(String curveName) {
    return curve25519.equalsIgnoreCase(curveName) || curve448.equalsIgnoreCase(curveName);
  }

  public static boolean isEdwardsOrMontgemoryCurve(String curveName) {
    return isEdwardsCurve(curveName) || isMontgemoryCurve(curveName);
  }

  public static boolean isEdwardsCurveKeyAlgName(String algName) {
    return ALG_Ed25519.equalsIgnoreCase(algName) || ALG_Ed448.equalsIgnoreCase(algName);
  }

  public static boolean isMontgemoryCurveKeyAlgName(String algName) {
    return ALG_X25519.equalsIgnoreCase(algName) || ALG_X448.equalsIgnoreCase(algName);
  }

  public static boolean isEdwardsOrMontgemoryCurveKeyAlgName(String algName) {
    return isEdwardsCurveKeyAlgName(algName) || isMontgemoryCurveKeyAlgName(algName);
  }

  public static boolean isEdwardsCurveKeyAlgId(ASN1ObjectIdentifier algId) {
    return id_Ed25519.equals(algId) || id_Ed448.equals(algId);
  }

  public static boolean isMontgemoryCurveKeyAlgId(ASN1ObjectIdentifier algId) {
    return id_X25519.equals(algId) || id_X448.equals(algId);
  }

  public static boolean isEdwardsOrMontgemoryCurveKeyAlgId(ASN1ObjectIdentifier algId) {
    return isEdwardsCurveKeyAlgId(algId) || isMontgemoryCurveKeyAlgId(algId);
  }

  public static int getKeyBitSizeForCurve(String curveName) {
    if (curve25519.equalsIgnoreCase(curveName)) {
      return 256;
    } else if (curve448.equalsIgnoreCase(curveName)) {
      return 448;
    } else if (edwards25519.equalsIgnoreCase(curveName)) {
      return 256;
    } else if (edwards448.equalsIgnoreCase(curveName)) {
      return 448;
    } else {
      return 0;
    }
  }

  public static int getPublicKeyByteSizeForCurve(String curveName) {
    if (curve25519.equalsIgnoreCase(curveName)) {
      return 32;
    } else if (curve448.equalsIgnoreCase(curveName)) {
      return 56;
    } else if (edwards25519.equalsIgnoreCase(curveName)) {
      return 32;
    } else if (edwards448.equalsIgnoreCase(curveName)) {
      return 57; // not 56
    } else {
      return 0;
    }
  }

  public static String getCurveForKeyAlgName(String keyAlg) {
    if (ALG_X25519.equalsIgnoreCase(keyAlg)) {
      return curve25519;
    } else if (ALG_X448.equalsIgnoreCase(keyAlg)) {
      return curve448;
    } else if (ALG_Ed25519.equalsIgnoreCase(keyAlg)) {
      return edwards25519;
    } else if (ALG_Ed448.equalsIgnoreCase(keyAlg)) {
      return edwards448;
    } else {
      return null;
    }
  }

  public static String getCurveForKeyAlgId(ASN1ObjectIdentifier algId) {
    if (id_X25519.equals(algId)) {
      return curve25519;
    } else if (id_X448.equals(algId)) {
      return curve448;
    } else if (id_Ed25519.equals(algId)) {
      return edwards25519;
    } else if (id_Ed448.equals(algId)) {
      return edwards448;
    } else {
      return null;
    }
  }

  public static String getKeyAlgNameForKeyAlg(AlgorithmIdentifier algId) {
    return getKeyAlgNameForKeyAlg(algId.getAlgorithm());
  }

  public static String getKeyAlgNameForKeyAlg(ASN1ObjectIdentifier algOid) {
    if (algOid.equals(id_Ed25519)) {
      return ALG_Ed25519;
    } else if (algOid.equals(id_Ed448)) {
      return ALG_Ed448;
    } else if (algOid.equals(id_X25519)) {
      return ALG_X25519;
    } else if (algOid.equals(id_X448)) {
      return ALG_X448;
    } else {
      return null;
    }
  }

  public static String getKeyAlgNameForCurve(String curveName) {
    if (curve25519.equalsIgnoreCase(curveName)) {
      return ALG_X25519;
    } else if (curve448.equalsIgnoreCase(curveName)) {
      return ALG_X448;
    } else if (edwards25519.equalsIgnoreCase(curveName)) {
      return ALG_Ed25519;
    } else if (edwards448.equalsIgnoreCase(curveName)) {
      return ALG_Ed448;
    } else {
      return null;
    }
  }

  public static ASN1ObjectIdentifier getKeyAlgIdForCurve(String curveName) {
    if (curve25519.equalsIgnoreCase(curveName)) {
      return id_X25519;
    } else if (curve448.equalsIgnoreCase(curveName)) {
      return id_X448;
    } else if (edwards25519.equalsIgnoreCase(curveName)) {
      return id_Ed25519;
    } else if (edwards448.equalsIgnoreCase(curveName)) {
      return id_Ed448;
    } else {
      return null;
    }
  }

  public static ASN1ObjectIdentifier getKeyAlgIdForKeyAlgName(String algName) {
    if (ALG_X25519.equalsIgnoreCase(algName)) {
      return id_X25519;
    } else if (ALG_X448.equalsIgnoreCase(algName)) {
      return id_X448;
    } else if (ALG_Ed25519.equalsIgnoreCase(algName)) {
      return id_Ed25519;
    } else if (ALG_Ed448.equalsIgnoreCase(algName)) {
      return id_Ed448;
    } else {
      return null;
    }
  }

}
