package com.om.filters;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.stereotype.Component;

/**
 * 实现 BeanDefinitionRegistryPostProcessor 的移除注册表Bean工厂后置处理器.
 */
@Component
public class RemoveRegistryBeanFactoryPostProcessor implements BeanDefinitionRegistryPostProcessor {
    /**
     * 在 BeanDefinitionRegistry 中后置处理 Bean 定义.
     *
     * @param registry BeanDefinitionRegistry
     * @throws BeansException Beans 异常
     */
    @Override
    public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) throws BeansException {
        if (registry.containsBeanDefinition("captchaController")) {
            registry.removeBeanDefinition("captchaController");
        }
    }

    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {

    }
}
