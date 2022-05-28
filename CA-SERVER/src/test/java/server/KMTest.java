package server;

import com.fxal.ca.cert.FileSNAllocator;
import com.fxal.ca.cert.SM2CertUtil;
import com.fxal.ca.protocol.GMObjectIdentifiers;
import com.fxal.ca.protocol.km.ApplyKeyRequestBuilder;
import com.fxal.ca.protocol.km.CARequestBuilder;
import com.fxal.ca.protocol.km.CARequester;
import com.fxal.ca.protocol.km.KSRequestBuilder;
import com.fxal.ca.protocol.km.asn1.*;
import com.fxal.ca.server.km.KMClient;
import com.fxal.ca.util.BCECUtil;
import com.fxal.ca.util.FileUtil;
import com.fxal.ca.util.SM2Util;
import com.fxal.ca.util.SM3Util;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * @author: caiming
 * @Date: 2021/8/11 15:06
 * @Description:
 */
public class KMTest {

    @Test
    public void applyKey() {
        try {
            KeyPair keyPair = SM2Util.generateKeyPair();

            FileSNAllocator allocator = new FileSNAllocator();
            BigInteger sn = allocator.nextSerialNumber();
            ASN1Integer userCertNo = new ASN1Integer(sn);
            AlgorithmIdentifier algId = new AlgorithmIdentifier(GMObjectIdentifiers.ecc_pub_key);
            SubjectPublicKeyInfo userPubKey = new SubjectPublicKeyInfo(algId, keyPair.getPublic().getEncoded());
            ASN1GeneralizedTime notBefore = new ASN1GeneralizedTime(new Date());
            ASN1GeneralizedTime notAfter = new ASN1GeneralizedTime(new Date());
            AppUserInfo appUserInfo = new AppUserInfo(userCertNo,userPubKey,notBefore,notAfter);
            ApplyKeyRequestBuilder applyKeyRequestBuilder = new ApplyKeyRequestBuilder(appUserInfo);
            ApplyKeyRequest applyKeyRequest = applyKeyRequestBuilder.build();
            KSRequestBuilder ksRequestBuilder = new KSRequestBuilder(getCAEntName());
            Request request = new Request(Request.TYPE_APPLY_KEY_REQ,applyKeyRequest);
            List<Request> requests = new ArrayList<>();
            requests.add(request);
            ksRequestBuilder.setRequestList(requests);
            ksRequestBuilder.setTaskNO(1L);
            KSRequest ksRequest = ksRequestBuilder.build();
            CARequestBuilder caRequestBuilder = new CARequestBuilder(ksRequest);
            caRequestBuilder.setCAPrivateKey(getCAPrivateKey());
             CARequest caRequest = caRequestBuilder.build();
            KMClient kmClient = new KMClient();
            kmClient.connectTest(6000,"127.0.0.1");
           // CARequester caRequester = new CARequester(kmClient);
          //  caRequester.executeCARequest(caRequest);
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    private X509Certificate getCAX509Cert() {
        try {
            X509Certificate cert = SM2CertUtil.getX509Certificate("target/test.root.ca.cer");
            return cert;
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return null;
    }

    private ECPrivateKeyParameters getCAPrivateKey(){
        try {
            byte[] privateKeyData = FileUtil.readFile("target/test.root.ca.pri");
            ECPrivateKeyParameters priKeyParameters = BCECUtil.convertSEC1ToECPrivateKey(privateKeyData);
            return priKeyParameters;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private EntName getCAEntName(){
        X509Certificate KMCert = getCAX509Cert();
        AlgorithmIdentifier hashAlgorithm = new AlgorithmIdentifier(GMObjectIdentifiers.sm_3);
        X500Name x500Name = X500Name.getInstance(KMCert.getIssuerX500Principal().getEncoded());
        GeneralName entName = new GeneralName(x500Name);
        byte[] hashData = SM3Util.hash(KMCert.getPublicKey().getEncoded());
        System.out.println(hashData.length);
        ASN1OctetString entPubKeyHash = new DEROctetString(hashData);
        ASN1Integer serialNumber = new ASN1Integer(KMCert.getSerialNumber());
        EntName KMEntName = new EntName(hashAlgorithm,entName,entPubKeyHash,serialNumber);
        return KMEntName;
    }


}
