package com.example.demo.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

//import javax.servlet.http.HttpServletRequest;
//import javax.servlet.http.HttpServletRequestWrapper;

public class TokenRequestWrapper extends HttpServletRequestWrapper {

    private final String token;

    public TokenRequestWrapper(HttpServletRequest request, String token) {
        super(request);
        this.token = token;
    }

    @Override
    public String getHeader(String name) {
        if ("Authorization".equals(name)) {
            return "Bearer " + token;
        }
        return super.getHeader(name);
    }
}

