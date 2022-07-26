package com.om.authing;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class AuthingInterceptorConfig implements WebMvcConfigurer {
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(AuthingInterceptor())
                .addPathPatterns("/query/**", "/authing/**");
    }

    @Bean
    public AuthingInterceptor AuthingInterceptor() {
        return new AuthingInterceptor();
    }
}
