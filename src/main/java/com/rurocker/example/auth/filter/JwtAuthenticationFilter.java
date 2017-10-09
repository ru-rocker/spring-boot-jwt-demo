package com.rurocker.example.auth.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import com.rurocker.example.auth.service.TokenAuthService;

@Component
public class JwtAuthenticationFilter extends GenericFilterBean {

	private static final String TOKEN_HEADER = "Authorization";

	@Autowired
	private TokenAuthService tokenAuthService;
	
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
			throws IOException, ServletException {
		
		String token = ((HttpServletRequest) request).getHeader(TOKEN_HEADER);

		Authentication authentication = tokenAuthService.getAuthentication(token);

		SecurityContextHolder.getContext().setAuthentication(authentication);
		filterChain.doFilter(request, response);
	}

}