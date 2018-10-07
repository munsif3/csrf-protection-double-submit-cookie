package com.munsif.ssd.csrfdoublesubmit.controller;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import com.munsif.ssd.csrfdoublesubmit.model.Blog;
import com.munsif.ssd.csrfdoublesubmit.model.User;
import com.munsif.ssd.csrfdoublesubmit.service.AuthenticationService;;

@Controller
public class MainController {

	private Logger logger = LoggerFactory.getLogger(MainController.class);

	@Autowired
	private AuthenticationService authenticationService;

	/**
	 * Handles Login request. Generates sessionCookie for keeping track of the
	 * session. Generates userCookie to keep track of the user who interacts with
	 * the application. Generates CSRF token cookie which will be used as the hidden
	 * field for "double submit"
	 * 
	 * @param credentials
	 * @param response
	 * @return request is redirected to the root request
	 */
	@PostMapping("/login")
	public String login(@ModelAttribute User credentials, HttpServletResponse response) {
		String username = credentials.getUsername();
		String password = credentials.getPassword();

		if (authenticationService.isValidUser(username, password)) {
			logger.debug("Successfully authenticated/validated user...");
			Cookie sessionCookie = new Cookie("sessionID", authenticationService.generateSessionId(username));
			Cookie userCookie = new Cookie("username", username);
			Cookie csrfTokenCookie = new Cookie("x-csrf-token", authenticationService.generateToken());
			response.addCookie(sessionCookie);
			response.addCookie(userCookie);
			response.addCookie(csrfTokenCookie);
			return "redirect:/";
		}
		logger.debug("Failed to authenticate user...");
		return "redirect:/login?status=failed";
	}

	/**
	 * Handles the Add Blog request. Extracts the cookies from the request (if any).
	 * Retrieves the sessionID from the cookie. Checks if the user is authenticated.
	 * Validates the CSRF Token provided, with that of what is in the HashMap.
	 * Returns with status as "success" or "failed"
	 * 
	 * @param blog
	 * @param request
	 * @return
	 */
	@PostMapping("/blog")
	public String blog(@ModelAttribute Blog blog, HttpServletRequest request) {
        logger.info("Request received for Add Blog..." + blog.toString());

        if (authenticationService.isAuthenticated(request.getCookies(), blog.getToken())){
            logger.error("Successfully user authenticated..");
            return "redirect:/home?status=success";
        }
        logger.error("User not authenticated...!");
        return "redirect:/home?status=failed";
	}

}
