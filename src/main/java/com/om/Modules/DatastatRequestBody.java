package com.om.Modules;

import java.util.ArrayList;
import java.util.HashMap;

public class DatastatRequestBody {
    private ArrayList<String> metrics;
    private HashMap<String, Object> variables;
    private String operation;
    private String start;
    private String end;

    public ArrayList<String> getmetrics() {
        return metrics;
    }

    public void setmetrics(ArrayList<String> metrics) {
        this.metrics = metrics;
    }

    public String getstart() {
        return start;
    }

    public void setstart(String start) {
        this.start = start;
    }

    public String getend() {
        return end;
    }

    public void setend(String end) {
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
