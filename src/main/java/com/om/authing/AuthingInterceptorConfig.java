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

package com.om.authing;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * WebMvcConfigurer 接口实现类，用于配置和注册 Authing 拦截器.
 */
@Configuration
public class AuthingInterceptorConfig implements WebMvcConfigurer {

    /**
     * 添加拦截器到拦截器注册表中.
     *
     * @param registry 拦截器注册表
     */
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(authingInterceptor())
                .addPathPatterns("/query/**", "/oneid/**");
    }

    /**
     * 创建 AuthingInterceptor Bean 实例.
     *
     * @return 返回创建的 AuthingInterceptor Bean
     */
    @Bean
    public AuthingInterceptor authingInterceptor() {
        return new AuthingInterceptor();
    }
}
