package org.prvn.labs.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SimpleController {

    @GetMapping("/hello")
    public String wishHello(){
        return "Hello World";
    }

    @GetMapping("/dummy")
    public String dummyMethod(){
        return "Hello World : I am dummy method";
    }
    @GetMapping("/special")
    public String specialMethod(){
        return "Hello World : I am Special method";
    }
}
