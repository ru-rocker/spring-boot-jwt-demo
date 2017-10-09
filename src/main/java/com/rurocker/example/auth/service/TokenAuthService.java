package com.rurocker.example.auth.service;

import java.io.IOException;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.UUID;

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
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class TokenAuthService {

	private static final String SECRET = "ru-rocker";
	private static final String TOKEN_PREFIX = "Bearer";
	private static final long EXPIRATION_TIME = 5 * 60 * 000; // 5 minutes

	@Autowired
	private ObjectMapper objectMapper;

	@Autowired
	private Consul consul;

	public String addAuthentication(Authentication authentication) throws IOException {
		
		Map<String,Object> map = new HashMap<>();
		map.put("username", authentication.getPrincipal().toString());
		map.put("roles", getRoles(authentication.getAuthorities()));
		
		String jti = UUID.randomUUID().toString();
		String value = objectMapper.writeValueAsString(map);
		addValue(jti, value);
		
		return Jwts.builder().setId(jti).setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
				.signWith(SignatureAlgorithm.HS512, SECRET.getBytes()).compact();
	}

	public Authentication getAuthentication(String token)
			throws JsonParseException, JsonMappingException, IOException {

		if (token == null) {
			throw new AuthenticationException("There is no Authorization token in the request header.");
		}

		String jti;
		try {
			jti = (String) Jwts.parser().setSigningKey(SECRET.getBytes())
					.parseClaimsJws(token.replace(TOKEN_PREFIX, "")).getBody().getId();
		} catch (ExpiredJwtException e) {
			removeKey(e.getClaims().getId());
			throw e;
		}
		AuthVO vo = parsePayload(getValue(jti));
		String user = vo.getUsername();
		String[] roles = vo.getRoles();

		return user != null ? new UsernamePasswordAuthenticationToken(user, null, getAuthorities(roles)) : null;
	}

	private String[] getRoles(Collection<? extends GrantedAuthority> coll){
		String[] roles = new String[coll.size()];
		int i = 0;
		for (GrantedAuthority ga : coll) {
			roles[i++] = ga.getAuthority();
		}
		return roles;
	}
	
	private void addValue(String key, String value){
		KeyValueClient kvClient = consul.keyValueClient();
		kvClient.putValue("session/" + key, value);
	}
	
	private void removeKey(String key) {
		KeyValueClient kvClient = consul.keyValueClient();
		kvClient.deleteKey("session/" + key);
	}

	private String getValue(String key) {
		KeyValueClient kvClient = consul.keyValueClient();
		return kvClient.getValueAsString("session/" + key).orNull();
	}

	private AuthVO parsePayload(String json) throws JsonParseException, JsonMappingException, IOException {
		if (json == null) {
			throw new AuthenticationException("No associated JWT ID is registered.");
		}
		return objectMapper.readValue(json, AuthVO.class);
	}

	private Collection<GrantedAuthority> getAuthorities(String[] roles) {
		Collection<GrantedAuthority> coll = new HashSet<>();
		for (String r : roles) {
			coll.add(new SimpleGrantedAuthority(r));
		}
		return coll;
	}
}
