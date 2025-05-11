package com.sciv;

import java.util.List;

public final class Policy {

    private final List<String> allowedSubjects;
    private final List<String> yaraRules;

    public Policy(List<String> allowedSubjects, List<String> yaraRules) {
        this.allowedSubjects = List.copyOf(allowedSubjects);
        this.yaraRules       = List.copyOf(yaraRules);
    }

    public List<String> allowedSubjects() { return allowedSubjects; }
    public List<String> yaraRules()       { return yaraRules; }
}