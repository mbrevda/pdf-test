package pdfSigner;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Calendar;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;

public class CreateSignature extends CreateSignatureBase {
    /**
     * Initialize the signature creator with a keystore and certificate password.
     *
     * @throws KeyStoreException         if the keystore has not been initialized
     *                                   (loaded)
     * @throws NoSuchAlgorithmException  if the algorithm for recovering the key
     *                                   cannot be found
     * @throws UnrecoverableKeyException if the given password is wrong
     * @throws CertificateException      if the certificate is not valid as signing
     *                                   time
     * @throws IOException               if no certificate could be found
     */
    public CreateSignature()
            throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException,
            IOException {
        super();
    }

    public void main(String pdfPath) throws IOException, GeneralSecurityException {
        setTsaUrl("http://ts.ssl.com");

        File inFile = new File(pdfPath);
        File outFile = new File(inFile.getParent(), "signed.pdf");
        FileOutputStream fileOS = new FileOutputStream(outFile);

        PDDocument doc = PDDocument.load(inFile);

        PDSignature signature = new PDSignature();
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
        signature.setName("CRM, LLC");
        signature.setLocation("New York, USA");
        signature.setReason("Document Certification");
        signature.setSignDate(Calendar.getInstance());

        SignatureOptions options = new SignatureOptions();
        options.setPreferredSignatureSize(SignatureOptions.DEFAULT_SIGNATURE_SIZE *
                20);

        doc.addSignature(signature, this, options);

        // Save the signed document
        doc.saveIncremental(fileOS);
        doc.close();
    }
}