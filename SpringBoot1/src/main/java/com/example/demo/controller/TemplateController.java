package com.example.demo.controller;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.bind.annotation.RequestMapping;

@Configuration
@RequestMapping("/")
public class TemplateController {

	@RequestMapping("/login")
	public String getLoginView() {
		return "login";
	}
	
	
	@RequestMapping("/courses")
	public String getCourses() {
		return "courses";
	}
}
