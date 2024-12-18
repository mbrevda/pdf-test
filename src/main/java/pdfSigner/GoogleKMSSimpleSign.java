package pdfSigner;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.cloudkms.v1.CloudKMS;
import com.google.api.services.cloudkms.v1.CloudKMSScopes;
import com.google.api.services.cloudkms.v1.model.AsymmetricSignRequest;
import com.google.api.services.cloudkms.v1.model.AsymmetricSignResponse;
import com.google.api.services.cloudkms.v1.model.Digest;
import com.google.auth.http.HttpCredentialsAdapter;
import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class GoogleKMSSimpleSign {

    public static CloudKMS createAuthorizedClient() throws IOException {
        // Create the credential
        HttpTransport transport = new NetHttpTransport();
        JsonFactory jsonFactory = new JacksonFactory();
        GoogleCredentials credential = GoogleCredentials.getApplicationDefault();

        // Depending on the environment that provides the default credentials (e.g.
        // Compute Engine, App
        // Engine), the credentials may require us to specify the scopes we need
        // explicitly.
        // Check for this case, and inject the scope if required.
        if (credential.createScopedRequired()) {
            credential = credential.createScoped(CloudKMSScopes.all());
        }

        return new CloudKMS.Builder(transport, jsonFactory, new HttpCredentialsAdapter(credential))
                .setApplicationName("CloudKMS snippets")
                .build();
    }

    /**
     * Create a signature for a message using a private key stored on Cloud KMS
     * <p>
     * Requires:
     * java.security.MessageDigest
     * java.util.Base64
     */
    public static byte[] signAsymmetric(byte[] message, CloudKMS client, String keyPath)
            throws IOException, NoSuchAlgorithmException {
        Digest digest = new Digest();

        // Note: some key algorithms will require a different hash function
        // For example, EC_SIGN_P384_SHA384 requires SHA-384

        // log message to stdout
        digest.encodeSha256(MessageDigest.getInstance("SHA-256").digest(message));

        return doSign(client, keyPath, digest);
    }

    public static byte[] signDigestAsymmetric(byte[] digestedMessage, CloudKMS client, String keyPath)
            throws IOException, NoSuchAlgorithmException {
        Digest digest = new Digest();

        digest.encodeSha256(digestedMessage);

        return doSign(client, keyPath, digest);
    }

    private static byte[] doSign(CloudKMS client, String keyPath, Digest digest) throws IOException {
        AsymmetricSignRequest signRequest = new AsymmetricSignRequest();
        signRequest.setDigest(digest);

        AsymmetricSignResponse response = client.projects()
                .locations()
                .keyRings()
                .cryptoKeys()
                .cryptoKeyVersions()
                .asymmetricSign(keyPath, signRequest)
                .execute();
        return Base64.getMimeDecoder().decode(response.getSignature());
    }

}