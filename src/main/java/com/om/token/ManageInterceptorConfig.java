/* This project is licensed under the Mulan PSL v2.
 You can use this software according to the terms and conditions of the Mulan PSL v2.
 You may obtain a copy of Mulan PSL v2 at:
     http://license.coscl.org.cn/MulanPSL2
 THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 PURPOSE.
 See the Mulan PSL v2 for more details.
 Create: 2023
*/

package com.om.token;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class ManageInterceptorConfig implements WebMvcConfigurer {
    /**
     * 配置拦截器，添加 OneIdManageInterceptor 拦截器并指定路径模式.
     *
     * @param registry 拦截器注册表
     */
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(oneIdManageInterceptor())
                .addPathPatterns("/query/**", "/oneid/**");
    }

    /**
     * 创建 OneIdManageInterceptor 拦截器 Bean.
     *
     * @return OneIdManageInterceptor 对象
     */
    @Bean
    public OneIdManageInterceptor oneIdManageInterceptor() {
        return new OneIdManageInterceptor();
    }

}
