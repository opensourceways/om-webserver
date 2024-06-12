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

package com.om.authing;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;

public class AuthingInterceptorConfigTest {
    private AuthingInterceptorConfig authingInterceptorConfigUnderTest;

    @Before
    public void setUp() {
        authingInterceptorConfigUnderTest = new AuthingInterceptorConfig();
    }

    @Test
    public void testAddInterceptors() {
        final InterceptorRegistry registry = new InterceptorRegistry();
        authingInterceptorConfigUnderTest.addInterceptors(registry);
    }

    @Test
    public void testAuthingInterceptor() {
        AuthingInterceptor result = authingInterceptorConfigUnderTest.authingInterceptor();
        Assert.assertNotNull(result);
    }
}
