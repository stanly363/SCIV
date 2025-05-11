package com.sciv;

import java.nio.file.Files;
import java.nio.file.Path;

public class EntropyAnalyser {
    public static double calculateEntropy(Path filePath) throws Exception {
        byte[] fileData = Files.readAllBytes(filePath);
        if (fileData.length == 0) return 0.0;

        int[] freq = new int[256];
        for (byte b : fileData) {
            freq[b & 0xFF]++;
        }

        double entropy = 0.0;
        for (int count : freq) {
            if (count == 0) continue;
            double p = (double) count / fileData.length;
            entropy -= p * (Math.log(p) / Math.log(2));
        }

        return entropy;
    }
}
