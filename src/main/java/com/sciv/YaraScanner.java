package com.sciv;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;


public class YaraScanner {

    /**
     * @param rulePath Path to the .yar/.yara file (filesystem or resource)
     * @param artifact Path to the file or ZIP to scan
     * @return List of matching output lines from YARA
     */
    public static List<String> scan(String rulePath, Path artifact) {
        List<String> hits = new ArrayList<>();

        // Use argument list rather than a shell command string
        ProcessBuilder pb = new ProcessBuilder(
            "yara",
            rulePath,
            artifact.toString()
        );
        pb.redirectErrorStream(true);

        try {
            Process process = pb.start();
            try (BufferedReader reader = new BufferedReader(
                     new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    hits.add(line);
                }
            }
            process.waitFor();
        } catch (IOException | InterruptedException e) {

        }

        return hits;
    }
}
