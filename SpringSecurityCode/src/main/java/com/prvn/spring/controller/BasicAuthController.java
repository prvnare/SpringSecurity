package com.prvn.spring.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

/**
 * File    : BasicAuthController
 * Created : 29/05/20
 * Last Changed  : 29/05/20 8:51 AM Fri
 * Author  : apple
 * History :
 * Initial impound
 */
@RestController
@RequestMapping("/auth")
@Slf4j
public class BasicAuthController {

    @GetMapping
    public String getDetails(Principal principal) {
        log.debug("GetDetails Method call : {}", principal.getName());
        return "Hello World  : ";
    }
}
