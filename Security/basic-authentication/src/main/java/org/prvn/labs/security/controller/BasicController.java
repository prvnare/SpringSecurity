package org.prvn.labs.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/hello")
public class BasicController {

    @GetMapping
    public String hello() {
        return "Hello World";
    }
}
