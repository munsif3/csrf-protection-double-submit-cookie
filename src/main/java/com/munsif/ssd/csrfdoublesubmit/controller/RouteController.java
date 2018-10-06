package com.munsif.ssd.csrfdoublesubmit.controller;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import com.munsif.ssd.csrfdoublesubmit.model.Blog;
import com.munsif.ssd.csrfdoublesubmit.model.User;
import com.munsif.ssd.csrfdoublesubmit.service.AuthenticationService;

@Controller
public class RouteController {

	private Logger logger = LoggerFactory.getLogger(RouteController.class);

	@Autowired
	AuthenticationService authenticationService;

	@GetMapping("/")
	public String loadPage(Model model, HttpServletRequest request) {
		if (!authenticationService.isAuthenticated(request.getCookies())) {
			return "redirect:/login";
		} else {
			return "redirect:/home";
		}
	}

	@GetMapping("/login")
	public String showLogin(Model model) {
		logger.debug("Redirecting to Login...");
		model.addAttribute("login", new User());
		return "login";
	}

	@GetMapping("/home")
	public String showHomePage(Model model, HttpServletRequest request) {
		logger.debug("Redirecting to Home...");
		model.addAttribute("home", new Blog());
		return "home";
	}
}
