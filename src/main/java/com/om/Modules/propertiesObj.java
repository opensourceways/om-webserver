package com.om.Modules;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.DependsOn;
import org.springframework.stereotype.Repository;
import org.springframework.util.DigestUtils;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * @author zhxia
 * @date 2020/11/5 16:24
 */
@DependsOn(value = {"openEuler", "openGauss", "openLookeng"})
@Repository
public class propertiesObj {
    static Properties properties = new Properties();

    String openEulerConfMd5;
    String openGaussConfMd5;
    String openLookengConfMd5;

    @Autowired
    private ApplicationContext applicationContext;

    static ScheduledExecutorService service = Executors
            .newSingleThreadScheduledExecutor();

    propertiesObj(ApplicationContext applicationContext) {

        // 间，第三个参数为定时执行的间隔第二个参数为首次执行的延时时时间
        service.scheduleAtFixedRate(new Runnable() {
            @Override
            public void run() {
                try {
                    updateCycle();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }, 5, 15, TimeUnit.SECONDS);
    }

    private void updateCycle() throws IOException {

        String openEneuler_conf_path = System.getProperty("user.dir") + "openEuler.properties";
        String eumd5 = DigestUtils.md5DigestAsHex(new FileInputStream(openEneuler_conf_path));
        if(!eumd5.equals(this.openEulerConfMd5)){
            this.openEulerConfMd5=eumd5;
            Properties openEneulerConf = readProperties(openEneuler_conf_path);
            setPropertiesValue(openEneulerConf, "openEuler");
        }

        String openGauss_conf_path = System.getProperty("user.dir") + "openGauss.properties";
        String gaussmd5 = DigestUtils.md5DigestAsHex(new FileInputStream(openGauss_conf_path));
        if(!gaussmd5.equals(this.openGaussConfMd5)) {
            this.openGaussConfMd5 = gaussmd5;
            Properties openGaussConf = readProperties(openGauss_conf_path);
            setPropertiesValue(openGaussConf, "openGauss");
        }

        String openLookeng_conf_path = System.getProperty("user.dir") + "openLookeng.properties";
        String lookengmd5 = DigestUtils.md5DigestAsHex(new FileInputStream(openLookeng_conf_path));
        if(!lookengmd5.equals(this.openLookengConfMd5)) {
            Properties openLookengConf = readProperties(openLookeng_conf_path);
            setPropertiesValue(openLookengConf, "openLookeng");
        }


    }

    private void setPropertiesValue(Properties openconf, String object) {
        openComObject bean = (openComObject) this.applicationContext.getBean(object);
        bean.setExtOs_index(openconf.get(IndexQueryEnum.EXTOS.getIndex()).toString());
        bean.setExtOs_queryStr(openconf.get(IndexQueryEnum.EXTOS.getQueryString()).toString());
        bean.setBusinessOsv_index(openconf.get(IndexQueryEnum.BUSINESSOSV.getIndex()).toString());
        bean.setBusinessOsv_queryStr(openconf.get(IndexQueryEnum.BUSINESSOSV.getQueryString()).toString());
        bean.setSigs_index(openconf.get(IndexQueryEnum.SIGS.getIndex()).toString());
        bean.setSigs_queryStr(openconf.get(IndexQueryEnum.SIGS.getQueryString()).toString());
        bean.setUsers_index(openconf.get(IndexQueryEnum.USERS.getIndex()).toString());
        bean.setUsers_queryStr(openconf.get(IndexQueryEnum.USERS.getQueryString()).toString());
        bean.setContributors_index(openconf.get(IndexQueryEnum.CONTRIUTORS.getIndex()).toString());
        bean.setContributors_queryStr(openconf.get(IndexQueryEnum.CONTRIUTORS.getQueryString()).toString());
        bean.setNoticeusers_index(openconf.get(IndexQueryEnum.NOTICEUSERS.getIndex()).toString());
        bean.setNoticeusers_queryStr(openconf.get(IndexQueryEnum.NOTICEUSERS.getQueryString()).toString());
        bean.setCommunitymembers_index(openconf.get(IndexQueryEnum.COMMUNITYMEMBERS.getIndex()).toString());
        bean.setCommunitymembers_queryStr(openconf.get(IndexQueryEnum.COMMUNITYMEMBERS.getQueryString()).toString());
    }

    private static Properties readProperties(String path) throws IOException {
        // 使用ClassLoader加载properties配置文件生成对应的输入流
        InputStream in = new FileInputStream(path);
        // 使用properties对象加载输入流
        properties.load(in);
        in.close();
        return properties;
    }


}
