package com.sciv;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**  
 * Verifies a file’s Authenticode signature against an X.509 certificate.  
 */
public class SignatureValidator {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * @param file path to the signed data
     * @param signaturePath path to the detached signature bytes
     * @param certPath path to the signing certificate (PEM or DER)
     * @return true if the signature validates against the certificate; false otherwise
     */
    public static boolean verify(Path file, Path signaturePath, Path certPath) {
        try {
            // read inputs
            byte[] data     = Files.readAllBytes(file);
            byte[] sigBytes = Files.readAllBytes(signaturePath);
            byte[] certBytes = Files.readAllBytes(certPath);

            // handle PEM vs DER
            String text = new String(certBytes, StandardCharsets.UTF_8);
            if (text.contains("-----BEGIN CERTIFICATE-----")) {
                String pem = text
                    .replace("-----BEGIN CERTIFICATE-----", "")
                    .replace("-----END CERTIFICATE-----", "")
                    .replaceAll("\\s", "");
                certBytes = java.util.Base64.getDecoder().decode(pem);
            }

            // load certificate
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate)
                cf.generateCertificate(new ByteArrayInputStream(certBytes));
            PublicKey key = cert.getPublicKey();

            // verify signature
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(key);
            verifier.update(data);
            return verifier.verify(sigBytes);

        } catch (IOException
               | CertificateException
               | NoSuchAlgorithmException
               | InvalidKeyException
               | SignatureException e) {
            // log the error; in a GUI/CLI you might show a user message instead
            System.err.println("Signature verification failed: " + e.getMessage());
            return false;
        }
    }
}
