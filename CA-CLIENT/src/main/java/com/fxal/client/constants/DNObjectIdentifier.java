package com.fxal.client.constants;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

/**
 * @author: caiming
 * @Date: 2022/5/18 9:05
 * @Description:
 */
public class DNObjectIdentifier {

    /**
     * country code - StringType(SIZE(2)).
     */
    public static final ASN1ObjectIdentifier C = new ASN1ObjectIdentifier("2.5.4.6");

    /**
     * organization - StringType(SIZE(1..64))
     */
    public static final ASN1ObjectIdentifier O = new ASN1ObjectIdentifier("2.5.4.10");

    /**
     * organizationIdentifier - StringType(SIZE(1..64))
     */
    public static final ASN1ObjectIdentifier organizationIdentifier
            = new ASN1ObjectIdentifier("2.5.4.97");

    /**
     * organizational unit name - StringType(SIZE(1..64))
     */
    public static final ASN1ObjectIdentifier OU = new ASN1ObjectIdentifier("2.5.4.11");

    /**
     * Title.
     */
    public static final ASN1ObjectIdentifier T = new ASN1ObjectIdentifier("2.5.4.12");

    /**
     * common name - StringType(SIZE(1..64))
     */
    public static final ASN1ObjectIdentifier CN = new ASN1ObjectIdentifier("2.5.4.3");

    /**
     * device serial number name - StringType(SIZE(1..64))
     */
    public static final ASN1ObjectIdentifier SN = new ASN1ObjectIdentifier("2.5.4.5");

    /**
     * street - StringType(SIZE(1..64))
     */
    public static final ASN1ObjectIdentifier street = new ASN1ObjectIdentifier("2.5.4.9");

    /**
     * device serial number name - StringType(SIZE(1..64))
     */
    public static final ASN1ObjectIdentifier serialNumber = SN;

    /**
     * locality name - StringType(SIZE(1..64))
     */
    public static final ASN1ObjectIdentifier L = new ASN1ObjectIdentifier("2.5.4.7");

    public static final ASN1ObjectIdentifier localityName = L;

    /**
     * state, or province name - StringType(SIZE(1..64))
     */
    public static final ASN1ObjectIdentifier ST = new ASN1ObjectIdentifier("2.5.4.8");

    /**
     * Naming attributes of type X520name.
     */
    public static final ASN1ObjectIdentifier surname = new ASN1ObjectIdentifier("2.5.4.4");

    public static final ASN1ObjectIdentifier givenName = new ASN1ObjectIdentifier("2.5.4.42");

    public static final ASN1ObjectIdentifier initials = new ASN1ObjectIdentifier("2.5.4.43");

    public static final ASN1ObjectIdentifier generation = new ASN1ObjectIdentifier("2.5.4.44");

    public static final ASN1ObjectIdentifier generationQualifier = generation;

    public static final ASN1ObjectIdentifier uniqueIdentifier
            = new ASN1ObjectIdentifier("2.5.4.45");

    /**
     * businessCategory - DirectoryString(SIZE(1..128)
     */
    public static final ASN1ObjectIdentifier businessCategory =
            new ASN1ObjectIdentifier("2.5.4.15");

    /**
     * postalCode - DirectoryString(SIZE(1..40)
     */
    public static final ASN1ObjectIdentifier postalCode = new ASN1ObjectIdentifier("2.5.4.17");

    /**
     * dnQualifier - DirectoryString(SIZE(1..64)
     */
    public static final ASN1ObjectIdentifier dnQualifier = new ASN1ObjectIdentifier("2.5.4.46");

    /**
     * RFC 3039 Pseudonym - DirectoryString(SIZE(1..64)
     */
    public static final ASN1ObjectIdentifier pseudonym = new ASN1ObjectIdentifier("2.5.4.65");

    /**
     * RFC 3039 DateOfBirth - GeneralizedTime - YYYYMMDD000000Z.
     */
    public static final ASN1ObjectIdentifier dateOfBirth =
            new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.1");

    /**
     * RFC 3039 PlaceOfBirth - DirectoryString(SIZE(1..128)
     */
    public static final ASN1ObjectIdentifier placeOfBirth =
            new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.2");

    /**
     * RFC 3039 Gender - PrintableString (SIZE(1))-- "M", "F", "m" or "f".
     */
    public static final ASN1ObjectIdentifier gender =
            new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.3");

    /**
     * RFC 3039 CountryOfCitizenship - PrintableString (SIZE (2))-- ISO 3166 codes only.
     */
    public static final ASN1ObjectIdentifier countryOfCitizenship
            = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.4");

    /**
     * RFC 3039 CountryOfResidence - PrintableString (SIZE (2))-- ISO 3166 codes only.
     */
    public static final ASN1ObjectIdentifier countryOfResidence =
            new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.5");

    /**
     * ISIS-MTT NameAtBirth - DirectoryString(SIZE(1..64)
     */
    public static final ASN1ObjectIdentifier nameAtBirth =
            new ASN1ObjectIdentifier("1.3.36.8.3.14");

    /**
     * RFC 3039 PostalAddress - SEQUENCE SIZE (1..6) OF
     * DirectoryString(SIZE(1..30))
     */
    public static final ASN1ObjectIdentifier postalAddress = new ASN1ObjectIdentifier("2.5.4.16");

    /**
     * RFC 2256 dmdName.
     */
    public static final ASN1ObjectIdentifier dmdName = new ASN1ObjectIdentifier("2.5.4.54");

    /**
     * id-at-telephoneNumber.
     */
    public static final ASN1ObjectIdentifier telephoneNumber
            = X509ObjectIdentifiers.id_at_telephoneNumber;

    /**
     * id-at-name.
     */
    public static final ASN1ObjectIdentifier name = X509ObjectIdentifiers.id_at_name;

    /**
     * Email address (RSA PKCS#9 extension) - IA5String.
     *
     * <p>Note: if you're trying to be ultra orthodox, don't use this! It shouldn't be in here.
     */
    public static final ASN1ObjectIdentifier emailAddress =
            PKCSObjectIdentifiers.pkcs_9_at_emailAddress;

    /**
     * more from PKCS#9.
     */
    public static final ASN1ObjectIdentifier unstructuredName =
            PKCSObjectIdentifiers.pkcs_9_at_unstructuredName;

    public static final ASN1ObjectIdentifier unstructuredAddress =
            PKCSObjectIdentifiers.pkcs_9_at_unstructuredAddress;

    /**
     * email address in certificates.
     */
    public static final ASN1ObjectIdentifier E = emailAddress;

    /*
     * others...
     */
    public static final ASN1ObjectIdentifier DC =
            new ASN1ObjectIdentifier("0.9.2342.19200300.100.1.25");

    /**
     * LDAP User id.
     */
    public static final ASN1ObjectIdentifier userid =
            new ASN1ObjectIdentifier("0.9.2342.19200300.100.1.1");

    /**
     * LDAP User id.
     */
    public static final ASN1ObjectIdentifier UID = userid;

}
