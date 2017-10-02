package com.rurocker.example.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.orbitz.consul.Consul;

@SpringBootApplication
public class AuthApplication {

	@Bean
	Consul getConsulClient(){
		return Consul.builder().build();
	}
	
	@Bean
	ObjectMapper getObjectMapper() {
		return new ObjectMapper();
	}

	public static void main(String[] args) {
		SpringApplication.run(AuthApplication.class, args);
	}
}
