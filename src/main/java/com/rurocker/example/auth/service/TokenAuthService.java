package com.rurocker.example.auth.service;

import java.io.IOException;
import java.util.Collection;
import java.util.HashSet;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.orbitz.consul.Consul;
import com.orbitz.consul.KeyValueClient;
import com.rurocker.example.auth.exception.AuthenticationException;
import com.rurocker.example.auth.vo.AuthVO;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;

@Component
public class TokenAuthService {

	private static final String TOKEN_HEADER = "Authorization";
	private static final String SECRET = "ru-rocker";
	private static final String TOKEN_PREFIX = "Bearer";

	@Autowired
	private ObjectMapper objectMapper;

	@Autowired
	private Consul consul;
	
	public Authentication getAuthentication(HttpServletRequest request)
			throws JsonParseException, JsonMappingException, IOException {
		String token = request.getHeader(TOKEN_HEADER);

		if (token == null) {
			throw new AuthenticationException("There is no Authorization token in the request header.");
		}

		String jti;
		try {
			jti = (String) Jwts.parser().setSigningKey(SECRET.getBytes())
					.parseClaimsJws(token.replace(TOKEN_PREFIX, "")).getBody().getId();
		} catch (ExpiredJwtException e) {
			System.out.println(e.getClaims().getId());
			removeKey(e.getClaims().getId());
			throw e;
		}
		AuthVO vo = parsePayload(getValue(jti));
		String user = vo.getUsername();
		String[] roles = vo.getRoles();

		return user != null ? new UsernamePasswordAuthenticationToken(user, null, getAuthorities(roles)) : null;
	}

	private void removeKey(String key) {
		KeyValueClient kvClient = consul.keyValueClient();
		kvClient.deleteKey(key);
	}

	private String getValue(String key) {
		KeyValueClient kvClient = consul.keyValueClient();
		return kvClient.getValueAsString("session/" + key).orNull();
	}

	private AuthVO parsePayload(String json) throws JsonParseException, JsonMappingException, IOException {
		if (json == null) {
			throw new AuthenticationException("No associated JWT ID is registered.");
		}
		AuthVO result = objectMapper.readValue(json, AuthVO.class);
		return result;
	}

	private Collection<GrantedAuthority> getAuthorities(String[] roles) {
		Collection<GrantedAuthority> coll = new HashSet<>();
		for (String r : roles) {
			coll.add(new SimpleGrantedAuthority(r));
		}
		return coll;
	}
}
