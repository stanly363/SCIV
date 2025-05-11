package com.sciv;

import java.awt.BorderLayout;
import java.awt.Desktop;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.datatransfer.DataFlavor;
import java.awt.dnd.DnDConstants;
import java.awt.dnd.DropTarget;
import java.awt.dnd.DropTargetAdapter;
import java.awt.dnd.DropTargetDropEvent;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertStore;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.zip.ZipFile;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;
import javax.swing.filechooser.FileNameExtensionFilter;

import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Swing-based GUI for the SCIV tool.
 */
public class SwingUI extends JFrame {

    private final JTextField zipField      = new JTextField();
    private final JTextField sigField      = new JTextField();
    private final JTextField certField     = new JTextField();

    private final JCheckBox checkOCSP      = new JCheckBox("Enable OCSP Revocation Check", false);
    private final JCheckBox checkExpiry    = new JCheckBox("Require Certificate Validity Dates", true);
    private final JCheckBox checkKeyUsage  = new JCheckBox("Require KeyUsage: digitalSignature", true);
    private final JCheckBox checkEKU       = new JCheckBox("Require EKU: codeSigning", true);

    private final JTextField hashField     = new JTextField();
    private final List<String> allowedHashes = new ArrayList<>();

    private final JTextField subjectField  = new JTextField();
    private final List<String> dynamicSubjects = new ArrayList<>();

    private final JTextField sbomNameField = new JTextField();
    private final JTextField sbomHashField = new JTextField();

    private static final String SBOM_RESOURCE       = "sbom.json";
    private static final String POLICY_RESOURCE     = "policy.yaml";
    private static final String SAMPLE_RULE         = "sample_rule.yar";
    private static final String TRUSTSTORE_RESOURCE = "truststore.jks";

    private static final Path SBOM_PATH        = Paths.get(SBOM_RESOURCE);
    private static final Path POLICY_PATH      = Paths.get(POLICY_RESOURCE);
    private static final Path SAMPLE_RULE_PATH = Paths.get(SAMPLE_RULE);
    private static final Path TRUSTSTORE_PATH  = Paths.get(TRUSTSTORE_RESOURCE);

    private final List<Path> additionalYaraRules = new ArrayList<>();
    private final JTextArea outputArea = new JTextArea();
    private final Path jarDir;

    public SwingUI() {
        super("SCIV – Supply Chain Integrity Verifier");

        // determine JAR directory (non-fatal)
        Path tmp;
        try {
            tmp = Paths.get(getClass()
                .getProtectionDomain()
                .getCodeSource()
                .getLocation()
                .toURI())
                .getParent();
        } catch (URISyntaxException e) {
            tmp = Paths.get("").toAbsolutePath();
            JOptionPane.showMessageDialog(this,
                "Warning: cannot resolve JAR directory, defaulting to cwd.",
                "Warning", JOptionPane.WARNING_MESSAGE);
        }
        jarDir = tmp;

        // extract bundled resources if missing
        try {
            ensureResource(SBOM_RESOURCE);
            ensureResource(POLICY_RESOURCE);
            ensureResource(SAMPLE_RULE);
            ensureResource(TRUSTSTORE_RESOURCE);
            ensureResource(".env");
        } catch (IOException ioe) {
            JOptionPane.showMessageDialog(this,
                "Failed to extract resources: " + ioe.getMessage(),
                "Error", JOptionPane.ERROR_MESSAGE);
        }

        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setSize(850, 800);
        setLocationRelativeTo(null);
        setLayout(new BorderLayout());

        JPanel form = new JPanel(new GridLayout(15, 3, 6, 6));
        form.setBorder(new EmptyBorder(10, 10, 10, 10));

        addField(form, "Artefact ZIP:", zipField, this::browseZip);
        addField(form, "Signature File:", sigField, this::browseSig);
        addField(form, "Certificate:", certField, this::browseCert);

        form.add(new JLabel("SBOM (fixed):"));
        form.add(new JLabel(SBOM_PATH.toString()));
        form.add(new JLabel());
        form.add(new JLabel("Policy (fixed):"));
        form.add(new JLabel(POLICY_PATH.toString()));
        form.add(new JLabel());

        addField(form, "Extra allowed hash:", hashField, this::onAddHash);
        addField(form, "Add Subject DN:", subjectField, this::onAddSubject);
        addField(form, "SBOM entry name:", sbomNameField, null);
        addField(form, "SBOM entry hash:", sbomHashField, this::onAddSbom);

        form.add(checkOCSP);
        form.add(checkExpiry);
        form.add(checkKeyUsage);
        form.add(checkEKU);
        form.add(new JLabel());
        form.add(new JLabel());

        JButton editYara   = new JButton("Edit Rule");
        JButton importYara = new JButton("Import Rule");
        editYara.addActionListener(e -> onEditYara());
        importYara.addActionListener(this::onImportYara);
        form.add(new JLabel("Edit default YARA rule:"));
        form.add(editYara);
        form.add(new JLabel());
        form.add(new JLabel("Import extra YARA rule:"));
        form.add(importYara);
        form.add(new JLabel());

        JButton verifyBtn = new JButton("Verify");
        verifyBtn.addActionListener(this::runVerification);
        form.add(new JLabel());
        form.add(verifyBtn);
        form.add(new JLabel());

        new DropTarget(form, DnDConstants.ACTION_COPY, new FileDropHandler(), true, null);

        add(form, BorderLayout.NORTH);

        outputArea.setEditable(false);
        outputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane scroll = new JScrollPane(outputArea);
        scroll.setBorder(new EmptyBorder(10, 10, 10, 10));
        add(scroll, BorderLayout.CENTER);
    }

    private void ensureResource(String res) throws IOException {
        Path target = Paths.get(res);
        if (Files.notExists(target)) {
            try (InputStream in = getClass().getClassLoader().getResourceAsStream(res)) {
                if (in == null) throw new FileNotFoundException(res + " not found");
                Files.copy(in, target);
            }
        }
    }

    private void addField(JPanel panel, String label, JTextField field, ActionListener action) {
        panel.add(new JLabel(label));
        panel.add(field);
        JButton btn = new JButton(action == null ? "Browse" : "Add");
        btn.addActionListener(action != null ? action : e -> {
            JFileChooser chooser = new JFileChooser();
            chooser.setFileFilter(new FileNameExtensionFilter(label, "*"));
            if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                field.setText(chooser.getSelectedFile().getAbsolutePath());
            }
        });
        panel.add(btn);
    }

    private void browseZip(ActionEvent e)  { browseTo(zipField,  "ZIP Files",       "zip"); }
    private void browseSig(ActionEvent e)  { browseTo(sigField,  "Signature Files", "sig","sig.b64"); }
    private void browseCert(ActionEvent e) { browseTo(certField, "Cert Files",      "crt","pem"); }

    private void browseTo(JTextField field, String desc, String... exts) {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileFilter(new FileNameExtensionFilter(desc, exts));
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            field.setText(chooser.getSelectedFile().getAbsolutePath());
        }
    }

    private class FileDropHandler extends DropTargetAdapter {
        @Override
        public void drop(DropTargetDropEvent evt) {
            try {
                evt.acceptDrop(DnDConstants.ACTION_COPY);
                @SuppressWarnings("unchecked")
                List<File> files = (List<File>) evt.getTransferable()
                    .getTransferData(DataFlavor.javaFileListFlavor);
                for (File f : files) {
                    String name = f.getName().toLowerCase(Locale.ROOT);
                    if (name.endsWith(".zip"))      zipField.setText(f.getPath());
                    else if (name.endsWith(".sig")) sigField.setText(f.getPath());
                    else if (name.endsWith(".crt")) certField.setText(f.getPath());
                    else if (name.endsWith(".yar")) additionalYaraRules.add(f.toPath());
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(
                    SwingUI.this,
                    "Drag-drop error: " + ex.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE
                );
            }
        }
    }

    private void onAddHash(ActionEvent e) {
        String h = hashField.getText().trim();
        if (h.matches("[0-9a-fA-F]{64}")) {
            allowedHashes.add(h.toLowerCase(Locale.ROOT));
            JOptionPane.showMessageDialog(this, "Allowed hash added:\n" + h);
            hashField.setText("");
        } else {
            JOptionPane.showMessageDialog(this, "Invalid SHA-256 hash.", "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void onAddSubject(ActionEvent e) {
        String dn = subjectField.getText().trim();
        if (dn.isBlank()) {
            JOptionPane.showMessageDialog(this, "Enter a non-empty DN.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        try {
            Yaml yaml = new Yaml();
            @SuppressWarnings("unchecked")
            Map<String, Object> policy = (Map<String, Object>) yaml.load(Files.newInputStream(POLICY_PATH));
            @SuppressWarnings("unchecked")
            List<String> allowed = (List<String>) policy.computeIfAbsent("allowedSubjects", k -> new ArrayList<>());
            if (!allowed.contains(dn)) {
                allowed.add(dn);
                DumperOptions opts = new DumperOptions();
                opts.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
                new Yaml(opts).dump(policy, Files.newBufferedWriter(POLICY_PATH));
                dynamicSubjects.add(dn);
                JOptionPane.showMessageDialog(this, "Subject DN added:\n" + dn);
            } else {
                JOptionPane.showMessageDialog(this, "DN already trusted.");
            }
            subjectField.setText("");
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(this, "Failed updating policy:\n" + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void onAddSbom(ActionEvent e) {
        String name = sbomNameField.getText().trim();
        String hash = sbomHashField.getText().trim().toLowerCase(Locale.ROOT);
        if (name.isBlank() || !hash.matches("[0-9a-f]{64}")) {
            JOptionPane.showMessageDialog(this, "Enter filename + valid SHA-256 hash.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        try {
            ObjectMapper mapper = new ObjectMapper();
            ObjectNode root = (ObjectNode) mapper.readTree(SBOM_PATH.toFile());
            ArrayNode comps = (ArrayNode) root.withArray("components");
            ObjectNode comp = mapper.createObjectNode();
            comp.put("type", "file");
            comp.put("name", name);
            comp.put("purl", name);
            ArrayNode hashes = mapper.createArrayNode();
            ObjectNode hnode = mapper.createObjectNode();
            hnode.put("alg", "SHA-256");
            hnode.put("content", hash);
            hashes.add(hnode);
            comp.set("hashes", hashes);
            comps.add(comp);
            mapper.writerWithDefaultPrettyPrinter().writeValue(SBOM_PATH.toFile(), root);
            JOptionPane.showMessageDialog(this, "SBOM entry added: " + name);
            sbomNameField.setText("");
            sbomHashField.setText("");
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(this, "Failed updating SBOM:\n" + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void onEditYara() {
        if (Desktop.isDesktopSupported()) {
            try {
                Desktop.getDesktop().open(SAMPLE_RULE_PATH.toFile());
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this, "Cannot open rule:\n" + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        } else {
            JOptionPane.showMessageDialog(this, "Desktop API not supported.", "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void onImportYara(ActionEvent e) {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileFilter(new FileNameExtensionFilter("YARA files", "yar", "yara"));
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            additionalYaraRules.add(chooser.getSelectedFile().toPath());
            JOptionPane.showMessageDialog(this, "Imported YARA rule:\n" + chooser.getSelectedFile());
        }
    }

    private void runVerification(ActionEvent ev) {
        try {
            String nl = System.lineSeparator();

            // sanitize and validate ZIP path
            String z = zipField.getText().trim();
            if (z.contains("..") || z.startsWith("/") || z.startsWith("\\")) {
                JOptionPane.showMessageDialog(this, "Invalid artifact path.", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            Path artifact = Paths.get(z);

            // load policy
            PolicyEngine policyEngine = PolicyEngine.load(POLICY_RESOURCE);

            // signature check
            boolean sigOk = SignatureValidator.verify(
                artifact,
                sanitizePath(sigField.getText()),
                sanitizePath(certField.getText())
            );
            StringBuilder out = new StringBuilder();
            out.append(sigOk
                ? String.format("✔ Signature Valid: Yes%s", nl)
                : String.format("❌ Signature Valid: No%s",  nl)
            );

            // certificate + OCSP
            X509Certificate x509;
            try (InputStream in = Files.newInputStream(sanitizePath(certField.getText()))) {
                x509 = (X509Certificate)
                    CertificateFactory.getInstance("X.509")
                                      .generateCertificate(in);
            }
            KeyStore ts = KeyStore.getInstance("JKS");
            String keyPass = loadKeyPass();
            if (keyPass == null) {
                JOptionPane.showMessageDialog(this,
                    "Keystore password not set",
                    "Error",
                    JOptionPane.ERROR_MESSAGE
                );
                return;
            }
            try (InputStream in = Files.newInputStream(TRUSTSTORE_PATH)) {
                ts.load(in, keyPass.toCharArray());
            }
            Set<TrustAnchor> anchors = new HashSet<>();
            for (Enumeration<String> al = ts.aliases(); al.hasMoreElements();) {
                String alias = al.nextElement();
                if (ts.isCertificateEntry(alias)) {
                    anchors.add(new TrustAnchor(
                        (X509Certificate) ts.getCertificate(alias),
                        null
                    ));
                }
            }
            CertPath cp = CertificateFactory.getInstance("X.509")
                .generateCertPath(List.of(x509));
            PKIXParameters params = new PKIXParameters(anchors);
            params.setRevocationEnabled(checkOCSP.isSelected());
            if (checkOCSP.isSelected()) {
                Security.setProperty("ocsp.enable", "true");
                CertStore store = CertStore.getInstance(
                    "Collection",
                    new CollectionCertStoreParameters(List.of(x509))
                );
                params.addCertStore(store);
                out.append(String.format("✔ OCSP revocation check: Enabled%s", nl));
            } else {
                out.append(String.format("✔ OCSP revocation check: Disabled%s", nl));
            }
            CertPathValidator.getInstance("PKIX").validate(cp, params);
            out.append(String.format("✔ Certificate chain: Valid%s", nl));

            // expiry
            if (checkExpiry.isSelected()) {
                try {
                    x509.checkValidity();
                    out.append(String.format("✔ Certificate expiry: Passed%s", nl));
                } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                    out.append(String.format("❌ Certificate expiry: Failed – %s%s", e.getMessage(), nl));
                }
            } else {
                out.append(String.format("✔ Certificate expiry: Skipped%s", nl));
            }

            // key usage
            if (checkKeyUsage.isSelected()) {
                boolean[] ku = x509.getKeyUsage();
                out.append(String.format(
                    ku != null && ku[0]
                        ? "✔ Key usage check: Passed%s"
                        : "❌ Key usage check: Failed%s",
                    nl
                ));
            } else {
                out.append(String.format("✔ Key usage check: Skipped%s", nl));
            }

            // EKU
            if (checkEKU.isSelected()) {
                List<String> ekus = x509.getExtendedKeyUsage();
                out.append(String.format(
                    ekus != null && ekus.contains("1.3.6.1.5.5.7.3.3")
                        ? "✔ EKU check: Passed%s"
                        : "❌ EKU check: Failed%s",
                    nl
                ));
            } else {
                out.append(String.format("✔ EKU check: Skipped%s", nl));
            }

            // subject DN
            String subj = x509.getSubjectX500Principal().getName();
            boolean subjOk = policyEngine.subjectAllowed(subj)
                              || dynamicSubjects.contains(subj);
            out.append(subjOk
                ? String.format("✔ Subject Allowed: Yes%s", nl)
                : String.format("❌ Subject Allowed: No%s",  nl)
            );

            // entropy
            double ent = EntropyAnalyser.calculateEntropy(artifact);
            out.append(String.format("✔ File entropy score: %.3f%s", ent, nl));
            if (ent > 7.0) {
                out.append(String.format("❌ High entropy detected: Potential packing or encryption.%s", nl));
            }

            // SBOM validation
            List<String> mismatches;
            try (InputStream sIn = Files.newInputStream(SBOM_PATH);
                 ZipFile     zf  = new ZipFile(artifact.toFile())) {
                mismatches = SBOMValidator.validate(sIn, zf);
            }
            mismatches.removeIf(m -> {
                String f = m.split(":")[0].trim();
                String actual = computeHashInZip(artifact, f);
                return allowedHashes.contains(actual);
            });
            if (mismatches.isEmpty()) {
                out.append(String.format("✔ SBOM check passed.%s", nl));
            } else {
                out.append(String.format("❌ SBOM mismatches:%s", nl));
                for (String m : mismatches) {
                    out.append(String.format("  • %s%n", m));
                }
            }

            // YARA scanning
            List<String> hits = new ArrayList<>();
            for (String rule : policyEngine.getPolicy().yaraRules()) {
                hits.addAll(YaraScanner.scan(rule, artifact));
            }
            for (Path extra : additionalYaraRules) {
                hits.addAll(YaraScanner.scan(extra.toString(), artifact));
            }
            if (hits.isEmpty()) {
                out.append(String.format("✔ No YARA issues found.%s", nl));
            } else {
                out.append(String.format("❌ YARA hits detected:%s", nl));
                for (String y : hits) {
                    out.append(String.format("  • %s%n", y));
                }
            }

            outputArea.setText(out.toString());

        } catch (Exception ex) {
            String nl = System.lineSeparator();
            outputArea.setText(String.format("❌ ERROR:%s%s", nl, ex.getMessage()));
        }
    }

    private Path sanitizePath(String input) throws IOException {
        String s = input.trim();
        if (s.contains("..") || s.startsWith("/") || s.startsWith("\\")) {
            throw new IOException("Invalid path");
        }
        return Paths.get(s);
    }

    private String computeHashInZip(Path zip, String filename) {
        try (FileSystem fs = FileSystems.newFileSystem(zip, Collections.emptyMap())) {
            byte[] data = Files.readAllBytes(fs.getPath(filename));
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(data);
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    private String loadKeyPass() throws IOException {
        Path envFile = jarDir.resolve(".env");
        Properties props = new Properties();
        try (BufferedReader r = Files.newBufferedReader(envFile)) {
            props.load(r);
        }
        String kp = props.getProperty("SCIV_KEY_PASS");
        if (kp == null) throw new IOException(".env missing SCIV_KEY_PASS");
        return kp;
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new SwingUI().setVisible(true));
    }
}
