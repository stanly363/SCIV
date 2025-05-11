package com.sciv;

import java.io.InputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/** Validates a CycloneDX SBOM against the ZIP’s contents. */
public class SBOMValidator {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static List<String> validate(InputStream sbomStream, ZipFile zip) {
        List<String> mismatches = new ArrayList<>();
        try {
            JsonNode root = MAPPER.readTree(sbomStream);
            JsonNode comps = root.path("components");
            if (!comps.isArray()) return mismatches;

            for (JsonNode comp : comps) {
                String name         = comp.path("name").asText();
                String filePath     = comp.path("purl").asText();
                String expectedHash = comp.path("hashes")
                                          .elements()
                                          .next()
                                          .path("content")
                                          .asText();

                ZipEntry entry = zip.getEntry(filePath);
                if (entry == null) {
                    mismatches.add(name + ": missing in artefact");
                    continue;
                }

                byte[] data       = zip.getInputStream(entry).readAllBytes();
                String actualHex  = sha256(data);

                // Convert hex strings to byte[] and compare in constant time
                byte[] expBytes = hexStringToBytes(expectedHash);
                byte[] actBytes = hexStringToBytes(actualHex);
                if (!MessageDigest.isEqual(expBytes, actBytes)) {
                    mismatches.add(name + ": hash drift");
                }
            }
        } catch (Exception e) {
            mismatches.add("SBOM validation error: " + e.getMessage());
        }
        return mismatches;
    }

    private static String sha256(byte[] input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest    = md.digest(input);
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static byte[] hexStringToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) (
                (Character.digit(hex.charAt(i), 16) << 4)
              + Character.digit(hex.charAt(i+1), 16)
            );
        }
        return data;
    }
}
