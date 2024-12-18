package pdfSigner;

import com.google.api.services.cloudkms.v1.CloudKMS;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;

import static pdfSigner.GoogleKMSSimpleSign.createAuthorizedClient;
import static pdfSigner.GoogleKMSSimpleSign.signAsymmetric;

public class GoogleKMSContentSigner implements ContentSigner {
    private ByteArrayOutputStream outputStream;
    private AlgorithmIdentifier sigAlgId;
    private String keyPath;
    private String googleAuthorisationKeyFileName;

    /**
     * Initialise Google KMS content signer
     * 
     * @param keyPath path to a KMS key
     */
    public GoogleKMSContentSigner(String keyPath) {
        this.keyPath = keyPath;
        this.sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256WITHRSAANDMGF1");
        this.outputStream = new ByteArrayOutputStream();
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return this.sigAlgId;
    }

    @Override
    public OutputStream getOutputStream() {
        return this.outputStream;
    }

    @Override
    public byte[] getSignature() {
        try {
            CloudKMS kms = createAuthorizedClient();

            byte[] signedAttributeSet = outputStream.toByteArray();

            return signAsymmetric(signedAttributeSet, kms, this.keyPath);

        } catch (IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException("Unable to sign with KMS");
        }
    }
}