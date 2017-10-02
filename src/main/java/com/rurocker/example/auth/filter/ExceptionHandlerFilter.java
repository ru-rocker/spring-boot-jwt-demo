package com.rurocker.example.auth.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.rurocker.example.auth.exception.AuthenticationException;
import com.rurocker.example.auth.vo.ErrorResponse;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;

@Component
public class ExceptionHandlerFilter extends OncePerRequestFilter {

	@Autowired
	private ObjectMapper objectMapper;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		try {
			filterChain.doFilter(request, response);
		} catch (ExpiredJwtException | UnsupportedJwtException | MalformedJwtException | SignatureException
				| IllegalArgumentException | AuthenticationException e) {
			handleError(response, e);
		}
	}

	private void handleError(HttpServletResponse response, Exception e) throws JsonProcessingException, IOException {

		ErrorResponse errorResponse = new ErrorResponse();
		errorResponse.setError(HttpStatus.UNAUTHORIZED.name());
		errorResponse.setStatus(HttpStatus.UNAUTHORIZED.value());
		errorResponse.setMessage(e.getMessage());
		errorResponse.setTimestamp(System.currentTimeMillis());

		response.setStatus(HttpStatus.UNAUTHORIZED.value());
		response.setContentType("application/json");
		response.getWriter().write(convertObjectToJson(errorResponse));

	}

	private String convertObjectToJson(Object object) throws JsonProcessingException {
		if (object == null) {
			return null;
		}
		return objectMapper.writeValueAsString(object);
	}

}