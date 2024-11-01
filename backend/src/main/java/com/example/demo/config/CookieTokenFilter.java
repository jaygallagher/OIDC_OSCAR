package com.example.demo.config;

//import javax.servlet.FilterChain;
//import javax.servlet.ServletException;
//import javax.servlet.http.Cookie;
//import javax.servlet.http.HttpServletRequest;
//import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.http.Cookie;

public class CookieTokenFilter extends OncePerRequestFilter {
/* 
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("access_token".equals(cookie.getName())) {
                    String token = cookie.getValue();
                    request = new TokenRequestWrapper(request, token);
                    break;
                }
            }
        }
        filterChain.doFilter(request, response);
    }
*/
    @Override
    protected void doFilterInternal(jakarta.servlet.http.HttpServletRequest request,
            jakarta.servlet.http.HttpServletResponse response, jakarta.servlet.FilterChain filterChain)
            throws jakarta.servlet.ServletException, IOException {
                Cookie[] cookies = request.getCookies();
                if (cookies != null) {
                    for (Cookie cookie : cookies) {
                        if ("access_token".equals(cookie.getName())) {
                            String token = cookie.getValue();
                            request = new TokenRequestWrapper(request, token);
                            break;
                        }
                    }
                }
                filterChain.doFilter(request, response);
    }
}
