package com.amarthya.springsecurity.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SpringSecurityController {


    @GetMapping("/")
    public String getData(){
        return "Hello Security";
    }

    @GetMapping("/csrftoken")
    public CsrfToken getCSRFToken(HttpServletRequest httpServletRequest){
        return (CsrfToken) httpServletRequest.getAttribute("_csrf");
    }

    @PostMapping("/post")
    public String getDataPost(){
        return "Hello Security post";
    }
}
