/* This project is licensed under the Mulan PSL v2.
 You can use this software according to the terms and conditions of the Mulan PSL v2.
 You may obtain a copy of Mulan PSL v2 at:
     http://license.coscl.org.cn/MulanPSL2
 THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 PURPOSE.
 See the Mulan PSL v2 for more details.
 Create: 2022
*/

package com.om.Utils;

import java.io.*;
import java.net.URL;
import org.yaml.snakeyaml.Yaml;


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

    public <T> T readLocalYaml(String yamlFile, Class<T> classType) {
        Yaml yaml = new Yaml();
        InputStream inputStream;
        T t = null;
        try {
            inputStream = new FileInputStream(yamlFile);
            t = yaml.loadAs(inputStream, classType);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return t;
    }

    public <T> T readYaml(String yamlFile) {
        Yaml yaml = new Yaml();
        InputStream inputStream;
        T t = null;
        try {
            inputStream = new FileInputStream(yamlFile);
            t = yaml.load(inputStream);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return t;
    }

    public String wget(String urlFile, String path) {
        Runtime runtime = Runtime.getRuntime();
        String cmd = String.format("wget -N -P %s %s", path, urlFile);
        System.out.println("cmd: " + cmd);

        String[] sp = urlFile.split("/");
        String localFile = path + sp[sp.length - 1];

        try {
            Process process = runtime.exec(cmd);
            InputStream is1 = process.getInputStream();
            InputStream is2 = process.getErrorStream();
            new Thread() {
                @Override
                public void run() {
                    BufferedReader bi = null;
                    String line;
                    try {
                        bi = new BufferedReader(new InputStreamReader(is1));
                        ;
                        while ((line = bi.readLine()) != null) {
                            System.out.println(line);
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    } finally {
                        if (bi != null) {
                            try {
                                bi.close();
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }
                    }
                }
            }.start();
            new Thread() {
                @Override
                public void run() {
                    BufferedReader bi = null;
                    String line;
                    try {
                        bi = new BufferedReader(new InputStreamReader(is2));
                        ;
                        while ((line = bi.readLine()) != null) {
                            System.out.println(line);
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    } finally {
                        if (bi != null) {
                            try {
                                bi.close();
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }
                    }
                }
            }.start();
            process.waitFor();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return localFile;
    }
}
