package com.om.Utils;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class CsvFileUtil {
    public static List<HashMap<String, Object>> readFile(String file) {
        try {
            BufferedReader textFile = new BufferedReader(new FileReader(new File(file)));
            String lineDta;
            int lineNum = 0;
            String[] header = null;
            ArrayList<HashMap<String, Object>> res = new ArrayList<>();
            while ((lineDta = textFile.readLine()) != null) {
                if (lineNum == 0) {
                    header = lineDta.split(",");
                } else {
                    HashMap<String, Object> dataMap = new HashMap<>();
                    String[] datas = lineDta.split(",");
                    for (int i = 0; i < header.length; i++) {
                        dataMap.put(header[i], datas[i]);
                    }
                    res.add(dataMap);
                }
                lineNum++;
            }

            return res;

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
