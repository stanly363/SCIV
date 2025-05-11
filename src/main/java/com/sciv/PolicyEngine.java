package com.sciv;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.List;
import java.util.Map;

import org.yaml.snakeyaml.Yaml;

/** Loads policy from a YAML resource and holds it immutably. */
public class PolicyEngine {

    private final Policy policy;

    
    private PolicyEngine(Policy policy) {
        this.policy = policy;
    }

    /** Factory method performs I/O before instantiation */
    @SuppressWarnings("unchecked")
    public static PolicyEngine load(String resourceName) {
        try (InputStream in = PolicyEngine.class
                                 .getClassLoader()
                                 .getResourceAsStream(resourceName)) {

            if (in == null) {
                throw new UncheckedIOException(
                    new FileNotFoundException("Resource not found: " + resourceName)
                );
            }

            Yaml yaml = new Yaml();
            Map<String, Object> m = yaml.load(in);
            List<String> subs  = (List<String>) m.getOrDefault("allowedSubjects", List.of());
            List<String> rules = (List<String>) m.getOrDefault("yaraRules",      List.of());
            Policy policy = new Policy(subs, rules);
            return new PolicyEngine(policy);

        } catch (IOException e) {
            throw new UncheckedIOException("Failed to load policy: " + resourceName, e);
        }
    }

    public Policy getPolicy() {
        return policy;
    }

    public boolean subjectAllowed(String subjectDn) {
        return policy.allowedSubjects().isEmpty()
            || policy.allowedSubjects().contains(subjectDn);
    }
}

