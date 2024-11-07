/* This project is licensed under the Mulan PSL v2.
 You can use this software according to the terms and conditions of the Mulan PSL v2.
 You may obtain a copy of Mulan PSL v2 at:
     http://license.coscl.org.cn/MulanPSL2
 THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 PURPOSE.
 See the Mulan PSL v2 for more details.
 Create: 2024
*/

package com.om.service;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.junit4.SpringRunner;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import static org.junit.Assert.assertEquals;

@RunWith(SpringRunner.class)
public class AuthingServiceTest {
    @Test
    public void testGetAbsoluteAccountNormal() throws NoSuchMethodException, IllegalAccessException, InvocationTargetException {
        AuthingService instance = new AuthingService();
        // 获取私有方法
        Method privateMethod = AuthingService.class.getDeclaredMethod("getAbsoluteAccount", String.class);
        // 设置可访问权限
        privateMethod.setAccessible(true);

        String result = (String) privateMethod.invoke(instance, "testUser");
        assertEquals("testUser", result);

        result = (String) privateMethod.invoke(instance, "12345");
        assertEquals("12345", result);
    }

    @Test
    public void testGetAbsoluteAccountPhone() throws NoSuchMethodException, IllegalAccessException, InvocationTargetException {
        AuthingService instance = new AuthingService();
        // 获取私有方法
        Method privateMethod = AuthingService.class.getDeclaredMethod("getAbsoluteAccount", String.class);
        // 设置可访问权限
        privateMethod.setAccessible(true);

        String result = (String) privateMethod.invoke(instance, "18425565213");
        assertEquals("+8618425565213", result);

        result = (String) privateMethod.invoke(instance, "+8618425565213");
        assertEquals("+8618425565213", result);
    }

    @Test
    public void testGetAbsoluteAccountEmail() throws NoSuchMethodException, IllegalAccessException, InvocationTargetException {
        AuthingService instance = new AuthingService();
        // 获取私有方法
        Method privateMethod = AuthingService.class.getDeclaredMethod("getAbsoluteAccount", String.class);
        // 设置可访问权限
        privateMethod.setAccessible(true);

        String result = (String) privateMethod.invoke(instance, "Test@qq.com");
        assertEquals("test@qq.com", result);

        result = (String) privateMethod.invoke(instance, "test@qq.com");
        assertEquals("test@qq.com", result);
    }
}