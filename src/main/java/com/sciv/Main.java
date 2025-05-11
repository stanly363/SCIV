package com.sciv;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipFile;

public class Main {
    private static void usage() {
        System.out.println("""
                           Usage: java -jar sciv.jar verify <artefact.zip>
                                  --sig    <sigfile>
                                  --cert   <cert>
                                  --sbom   <sbom.json>
                                  --policy <policy.yaml>""");

    }
    public static void main(String[] args) throws Exception {
        if (args.length < 2 || !"verify".equals(args[0])) { usage(); return; }

        Path artefact = Path.of(args[1]);
        Path sig = null, cert = null, sbom = null, policyFile = null;
        
        for (int i=2;i<args.length-1;i++) {
            switch (args[i]) {
                case "--sig" -> sig = Path.of(args[++i]);
                case "--cert" -> cert = Path.of(args[++i]);
                case "--sbom" -> sbom = Path.of(args[++i]);
                case "--policy" -> policyFile = Path.of(args[++i]);
                default -> {}
            }
        }
        if (sig==null||cert==null||sbom==null||policyFile==null) { usage(); return; }
        boolean sigOk = SignatureValidator.verify(artefact, sig, cert);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate x509;
        try (InputStream in = Files.newInputStream(cert)) {
            x509 = (X509Certificate) cf.generateCertificate(in);
        }
        String subj = x509.getSubjectX500Principal().getName();
        PolicyEngine engine = PolicyEngine.load(policyFile.toString());
        boolean subjectAllowed = engine.subjectAllowed(subj);
        List<String> sbomMismatch;
        try (InputStream sbomStream = Files.newInputStream(sbom);
            ZipFile zipFile       = new ZipFile(artefact.toFile())) {
            sbomMismatch = SBOMValidator.validate(sbomStream, zipFile);
        }
        List<String> yaraHits = new ArrayList<>();
        for (String rulePath : engine.getPolicy().yaraRules()) {
            String resourcePath = "/" + rulePath.replace("\\", "/");
            yaraHits.addAll(YaraScanner.scan(resourcePath, artefact));
        }
        double entropy = EntropyAnalyser.calculateEntropy(artefact);
        if (entropy > 7.0) {
            System.out.println("⚠️ High entropy detected: possible packed/encrypted binary.");
        } else {
            System.out.println("✔️ Entropy level normal.");
        }
        Report rep = new Report(sigOk, subjectAllowed, sbomMismatch, yaraHits);
        System.out.println(rep.toJson());
        System.out.println("DEBUG subject: " + subj);
        if (!sigOk || !subjectAllowed || !sbomMismatch.isEmpty() || !yaraHits.isEmpty()) {
            System.exit(1);
        }
    }
}

