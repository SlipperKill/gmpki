package com.fxal.client.cmp;

import com.fxal.client.constants.GMObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.io.OutputStream;

/**
 * @author: caiming
 * @Date: 2022/5/25 15:51
 * @Description:
 */
public class SM3DigestCalculatorProvider implements DigestCalculatorProvider {
    @Override
    public DigestCalculator get(AlgorithmIdentifier algorithmIdentifier) throws OperatorCreationException {
        final SM3DigestCalculatorProvider.DigestOutputStream var3 = new DigestOutputStream(new SM3Digest());
        return new DigestCalculator() {
            public AlgorithmIdentifier getAlgorithmIdentifier() {
                return new AlgorithmIdentifier(GMObjectIdentifiers.sm_3);
            }

            public OutputStream getOutputStream() {
                return var3;
            }

            public byte[] getDigest() {
                return var3.getDigest();
            }
        };
    }

    private class DigestOutputStream extends OutputStream {
        private Digest dig;

        DigestOutputStream(Digest var2) {
            this.dig = var2;
        }

        public void write(byte[] var1, int var2, int var3) throws IOException {
            this.dig.update(var1, var2, var3);
        }

        public void write(byte[] var1) throws IOException {
            this.dig.update(var1, 0, var1.length);
        }

        public void write(int var1) throws IOException {
            this.dig.update((byte)var1);
        }

        byte[] getDigest() {
            byte[] var1 = new byte[this.dig.getDigestSize()];
            this.dig.doFinal(var1, 0);
            return var1;
        }
    }
}
