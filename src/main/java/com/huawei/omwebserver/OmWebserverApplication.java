package com.huawei.omwebserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan(basePackages = { "com.huawei.*" })
public class OmWebserverApplication {

	public static void main(String[] args) {
		SpringApplication.run(OmWebserverApplication.class, args);
	}

}
