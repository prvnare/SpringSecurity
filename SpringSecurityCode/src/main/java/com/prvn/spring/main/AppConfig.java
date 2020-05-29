package com.prvn.spring.main;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * File    : AppConfig
 * Created : 29/05/20
 * Last Changed  : 29/05/20 8:35 AM Fri
 * Author  : apple
 * History :
 * Initial impound
 */
@SpringBootApplication
@Slf4j
public class AppConfig {
    public static void main(String[] args) {
        SpringApplication.run(AppConfig.class, args);
        log.debug("App has been started : ");
    }
}
