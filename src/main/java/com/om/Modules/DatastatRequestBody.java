package com.om.Modules;

import java.util.ArrayList;
import java.util.HashMap;

public class DatastatRequestBody {
    private ArrayList<String> metrics;
    private HashMap<String, Object> variables;
    private String operation;
    private long start;
    private long end;

    public ArrayList<String> getmetrics() {
        return metrics;
    }

    public void setmetrics(ArrayList<String> metrics) {
        this.metrics = metrics;
    }

    public long getstart() {
        return start;
    }

    public void setstart(long start) {
        this.start = start;
    }

    public long getend() {
        return end;
    }

    public void setend(long end) {
        this.end = end;
    }

    public HashMap<String, Object> getvariables() {
        return variables;
    }

    public void setvariables(HashMap<String, Object> variables) {
        this.variables = variables;
    }
    
    public String geoperation() {
        return operation;
    }

    public void setoperation(String operation) {
        this.operation = operation;
    }
}
