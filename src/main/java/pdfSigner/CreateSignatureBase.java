package pdfSigner;

import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.Attributes;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPException;

import java.io.*;
import java.net.URL;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

public abstract class CreateSignatureBase implements SignatureInterface {
    private Certificate[] certificateChain;
    private String tsaUrl;
    private TSAClient tsaClient;
    private boolean externalSigning;

    public CreateSignatureBase()
            throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, IOException,
            CertificateException {
    }

    public final void setCertificateChain(final Certificate[] certificateChain) {
        this.certificateChain = certificateChain;
    }

    public void setTsaUrl(String tsaUrl) {
        this.tsaUrl = tsaUrl;
    }

    public void setTsaClient(TSAClient tsaClient) {
        this.tsaClient = tsaClient;
    }

    public TSAClient getTsaClient() {
        return tsaClient;
    }

    protected void buildCertificateChain() throws CertificateException, IOException {
        Certificate[] certChain = new Certificate[] {
                getCertificate("../certs/cert.crt"),
                getCertificate("../certs/CLIENT_CERTIFICATE_INTERMEDIATE_CA_RSA_R2.crt"),
                getCertificate("../certs/ROOT_CERTIFICATION_AUTHORITY_RSA.crt"),
        };
        setCertificateChain(certChain);
    }

    protected X509Certificate getCertificate(String fileName) throws CertificateException, FileNotFoundException {
        InputStream in = new FileInputStream(fileName);

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        final Collection<? extends Certificate> certs = (Collection<? extends Certificate>) certFactory
                .generateCertificates(in);

        return (X509Certificate) certs.iterator().next();
    }

    /**
     * SignatureInterface implementation.
     *
     * This method will be called from inside of the pdfbox and create the PKCS #7
     * signature.
     * The given InputStream contains the bytes that are given by the byte range.
     *
     * This method is for internal use only.
     *
     * Use your favorite cryptographic library to implement PKCS #7 signature
     * creation.
     *
     * @throws IOException
     */
    @Override
    public byte[] sign(InputStream content) throws IOException {
        try {
            buildCertificateChain();
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            X509Certificate signingCertificate = (X509Certificate) certificateChain[0];

            ContentSigner googleKMSContentSigner = new GoogleKMSContentSigner(
                    "REPLACE_WITH_REAL_KMS_PATH");

            gen.addSignerInfoGenerator(
                    new JcaSignerInfoGeneratorBuilder(
                            new JcaDigestCalculatorProviderBuilder().build())
                            .build(googleKMSContentSigner, signingCertificate));

            gen.addCertificates(new JcaCertStore(Arrays.asList(certificateChain)));

            CMSProcessableByteArray msg = new CMSProcessableByteArray(content.readAllBytes());
            CMSSignedData signedData = gen.generate(msg, true);

            if (tsaUrl != null) {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                this.setTsaClient(new TSAClient(new URL(tsaUrl), null, null, digest));
                try {
                    signedData = signTimeStamps(signedData);
                } catch (TSPException e) {
                    throw new IOException(e);
                }
            }

            return signedData.getEncoded();
        } catch (GeneralSecurityException | CMSException | OperatorCreationException e) {
            throw new IOException(e);
        }
    }

    /**
     * Set if external signing scenario should be used.
     * If {@code false}, SignatureInterface would be used for signing.
     * <p>
     * Default: {@code false}
     * </p>
     * 
     * @param externalSigning {@code true} if external signing should be performed
     */
    public void setExternalSigning(boolean externalSigning) {
        this.externalSigning = externalSigning;
    }

    public boolean isExternalSigning() {
        return externalSigning;
    }

    /**
     * We just extend CMS signed Data
     *
     * @param signedData
     *                   ´Generated CMS signed data
     * @return CMSSignedData Extended CMS signed data
     * @throws IOException
     * @throws org.bouncycastle.tsp.TSPException
     */
    private CMSSignedData signTimeStamps(CMSSignedData signedData) throws IOException, TSPException {
        SignerInformationStore signerStore = signedData.getSignerInfos();
        List<SignerInformation> newSigners = new ArrayList<SignerInformation>();

        for (SignerInformation signer : signerStore.getSigners()) {
            newSigners.add(signTimeStamp(signer));
        }

        // TODO do we have to return a new store?
        return CMSSignedData.replaceSigners(signedData, new SignerInformationStore(newSigners));
    }

    /**
     * We are extending CMS Signature
     *
     * @param signer
     *               information about signer
     * @return information about SignerInformation
     */
    private SignerInformation signTimeStamp(SignerInformation signer) throws IOException, TSPException {
        AttributeTable unsignedAttributes = signer.getUnsignedAttributes();

        ASN1EncodableVector vector = new ASN1EncodableVector();
        if (unsignedAttributes != null) {
            vector = unsignedAttributes.toASN1EncodableVector();
        }

        byte[] token = getTsaClient().getTimeStampToken(signer.getSignature());
        ASN1ObjectIdentifier oid = PKCSObjectIdentifiers.id_aa_signatureTimeStampToken;
        ASN1Encodable signatureTimeStamp = new Attribute(oid, new DERSet(ASN1Primitive.fromByteArray(token)));

        vector.add(signatureTimeStamp);
        Attributes signedAttributes = new Attributes(vector);

        SignerInformation newSigner = SignerInformation.replaceUnsignedAttributes(signer,
                new AttributeTable(signedAttributes));

        // TODO can this actually happen?
        if (newSigner == null) {
            return signer;
        }

        return newSigner;
    }
}