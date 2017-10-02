package com.rurocker.example.auth.controller;

import java.util.Date;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.rurocker.example.auth.vo.Greeting;


@RestController
@RequestMapping("/api")
public class GreetingController {

	private static final String template = "Hello, %s!";

	@RequestMapping("/greeting")
	public Greeting greeting(@RequestParam(value = "name", defaultValue = "World") String name) {
		return new Greeting(new Date(), String.format(template, name));
	}
}
