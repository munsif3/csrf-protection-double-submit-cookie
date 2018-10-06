package com.munsif.ssd.csrfdoublesubmit.controller;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.munsif.ssd.csrfdoublesubmit.model.CredentialStore;
import com.munsif.ssd.csrfdoublesubmit.service.AuthenticationService;

@RestController
public class TokenController {

	private Logger logger = LoggerFactory.getLogger(TokenController.class);

	@Autowired
	private AuthenticationService authenticationService;

	/**
	 * Acts as the Token end-point to send the CSRF Token to the front-end. Extracts
	 * the session ID from the request cookies. Retrieves the Token from the
	 * HashMap.
	 * 
	 * @param request
	 * @return
	 */
	@GetMapping(path = "/token")
	public String token(HttpServletRequest request) {
		logger.debug("Synchronizer token requested...");
		String sessionId = authenticationService.sessionIdFromCookies(request.getCookies());
		String token = "";
		if (sessionId != null) {
			token = new CredentialStore().findTokenForSession(sessionId);
			logger.info("Successfully authenticated user session...");
			if (token != null) {
				return token;
			}
		}
		logger.error("Failed to authenticate user!");
		return token;
	}
}
