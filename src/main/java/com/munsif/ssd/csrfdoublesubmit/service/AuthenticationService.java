package com.munsif.ssd.csrfdoublesubmit.service;

import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.servlet.http.Cookie;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.munsif.ssd.csrfdoublesubmit.model.CredentialStore;
import com.munsif.ssd.csrfdoublesubmit.model.User;
import com.munsif.ssd.csrfdoublesubmit.util.ApplicationConfig;
import com.munsif.ssd.csrfdoublesubmit.util.HashUtil;

@Service
public class AuthenticationService {

	private Logger logger = LoggerFactory.getLogger(AuthenticationService.class);
	CredentialStore userCredentialsStore = new CredentialStore();

	@Autowired
	private ApplicationConfig applicationConfig;

	/**
	 * Check if the credentials entered in the UI are of the valid user available in
	 * the HashMap. Compares the username and the hash value of the typed in
	 * password.
	 * 
	 * @param username
	 * @param password
	 * @return
	 */
	public boolean isValidUser(String username, String password) {
		logger.debug("Authenticating User...");
		try {
			return (username.equalsIgnoreCase(applicationConfig.getAuthUser())
					&& HashUtil.getHashValue(password).equalsIgnoreCase(applicationConfig.getPassword()));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return false;
		}
	}

	/**
	 * Checks if the logged in user is already authenticated by checking the cookies
	 * that came along the request. Extracts the session Id and the username from
	 * the two cookies (if available).
	 * 
	 * @param cookies
	 * @return
	 */
	public boolean isAuthenticated(Cookie[] cookies) {
		int l = cookies != null ? cookies.length : -1;
		logger.debug("isAuthenticated one param! " + l);
		String session = "";
		String username = "";

		if (cookies != null && cookies.length > 0) {
			for (Cookie cookie : cookies) {
				if (cookie.getName().equals("sessionID")) {
					session = cookie.getValue();
				} else if (cookie.getName().equals("username")) {
					username = cookie.getValue();
				}
			}
		}
		return (isUserSessionValid(username, session));
	}

	/**
	 * Checks if the logged in user is already authenticated by checking the cookies
	 * that came along the request. Extracts the session Id and the username from
	 * the two cookies (if available), and also the X-CSRF-Token.
	 * 
	 * @param cookies
	 * @return
	 */
	public boolean isAuthenticated(Cookie[] cookies, String csrfToken) {
		logger.debug("isAuthenticated? " + cookies.length + ", " + csrfToken);
		Map<String, String> cookieStore = new HashMap<>();
		if (cookies != null && cookies.length > 0) {
			for (Cookie cookie : cookies) {
				cookieStore.put(cookie.getName(), cookie.getValue());
			}
		}
		
		logger.debug("Cookie store size , " + cookieStore.size());

		// Check if the user session is valid and if the both the csrf tokens match
		if (isUserSessionValid(cookieStore.get("username"), cookieStore.get("sessionID"))
				&& validateCSRFToken(cookieStore.get("x-csrf-token"), csrfToken)) {
			logger.info("Token validated...");
			return true;
		}

		return false;
	}

	/**
	 * Checks if a user session is available and if so, valid by checking if the
	 * passed session id is the same as what is in the Credentials Store HashMap
	 * 
	 * @param username
	 * @param sessionId
	 * @return
	 */
	public boolean isUserSessionValid(String username, String sessionId) {
		logger.debug("Checking if user session is valid... " + username + ", " + sessionId);
		if (userCredentialsStore.findCredentials(username) != null) {
			return sessionId.equals(userCredentialsStore.findCredentials(username).getSessionID());
		}
		return false;
	}

	/**
	 * Generate a session Id and token, and store it in the Credential Store HashMap
	 * against the username
	 * 
	 * @param username
	 * @return
	 */
	public String generateSessionId(String username) {
		logger.debug("Generating user session...");
		User credentials = userCredentialsStore.findCredentials(username);
		String sessionId = UUID.randomUUID().toString();

		credentials.setSessionID(sessionId);
		userCredentialsStore.addCredentials(credentials);

		logger.debug("Storing user session...");
		return sessionId;
	}

	/**
	 * Generate a CSRF token and return
	 * 
	 * @return
	 */
	public String generateToken() {
		return UUID.randomUUID().toString();
	}

	/**
	 * Extracts the session Id from the request cookies (if any)
	 * 
	 * @param cookies
	 * @return
	 */
	public String sessionIdFromCookies(Cookie[] cookies) {
		if (null != cookies && cookies.length > 0) {
			for (Cookie cookie : cookies) {
				if (cookie.getName().equals("sessionID")) {
					return cookie.getValue();
				}
			}
		}
		return null;
	}

	/**
	 * Validates if the CSRF token is valid
	 *
	 * @param tokenFromCookie
	 * @param tokenFromForm
	 * @return
	 */
	public boolean validateCSRFToken(String tokenFromCookie, String tokenFromForm) {
		return (tokenFromCookie.equals(tokenFromForm));
	}
}
