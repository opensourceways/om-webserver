package com.om.Utils;

import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.net.URL;

public class YamlUtil {
    public <T> T readUrlYaml(String yamlUrl, Class<T> classType) {
        Yaml yaml = new Yaml();
        InputStream inputStream;
        T t = null;
        try {
            URL url = new URL(yamlUrl);
            inputStream = url.openStream();
            t = yaml.loadAs(inputStream, classType);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return t;
    }
}
