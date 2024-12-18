package pdfSigner;

import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * Hello world!
 */
public class App {
    public static void main(String[] args) {
        // System.out.println("Hello World!");
        // Example code to load a PDF document using PDFBox
        try {
            CreateSignature signer = new CreateSignature();
            signer.main("./in.pdf");
        } catch (IOException | GeneralSecurityException e) {
            e.printStackTrace();
        }
    }
}