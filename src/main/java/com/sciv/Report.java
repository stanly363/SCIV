package com.sciv;

import java.util.List;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public final class Report {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final boolean signatureOk;
    private final boolean entropyOk;
    private final List<String> sbomMismatches;
    private final List<String> yaraHits;

    public Report(boolean signatureOk,
                  boolean entropyOk,
                  List<String> sbomMismatches,
                  List<String> yaraHits) {

        this.signatureOk    = signatureOk;
        this.entropyOk      = entropyOk;
        this.sbomMismatches = List.copyOf(sbomMismatches); 
        this.yaraHits       = List.copyOf(yaraHits);       
    }


    public boolean signatureOk()            { return signatureOk; }
    public boolean entropyOk()              { return entropyOk;   }
    public List<String> sbomMismatches()    { return sbomMismatches; }
    public List<String> yaraHits()          { return yaraHits; }

    public String toJson() {
        try {
            return MAPPER.writeValueAsString(this);
        } catch (JsonProcessingException e) {

            throw new IllegalStateException("Cannot serialise report", e);
        }
    }
}
