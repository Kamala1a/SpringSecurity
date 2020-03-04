package com.springSecurity;

import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Controller
@EnableWebSecurity
public class StudentController {

	@RequestMapping(path = "/home")
	public String getStudent() {
		Student student = new Student();
		return "WELCOME";
	}
	
}
