package com.om.dao;


import com.om.omwebserver.OmWebserverApplication;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(classes = OmWebserverApplication.class)
public class AuthingUserDaoLinkConnListGiteeTest {
    @Autowired
    private AuthingUserDao dao;

    /**
     * 测试只有gitee企业身份源，而没有社会身份源.
     */
    @Test
    void test_gitee_authorization_url() {
        String token = "";
        List<Map<String, String>> res = dao.linkConnList(token);
        for (Map<String, String> map : res) {
            if ("enterprise_gitee".equals(map.get("name"))) {
                assertEquals(map.get("authorizationUrl"), "");
            }
        }
    }

    /**
     * 测试只有gitee社会身份源，而没有企业身份源.
     */
    @Test
    void test_gitee_authorization_url_social() {
        String token = "";
        List<Map<String, String>> res = dao.linkConnList(token);
        for (Map<String, String> map : res) {
            if ("enterprise_gitee".equals(map.get("name"))) {
                assertEquals(map.get("authorizationUrl"), "");
            }
        }
    }
}
