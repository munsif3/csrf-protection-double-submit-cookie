package com.munsif.ssd.csrfdoublesubmit.model;

import java.util.HashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Holds two HashMaps. One for storing User object against username and the
 * second is to store Token against session ID
 * 
 * @author munsif
 *
 */
public class CredentialStore {

	private Logger logger = LoggerFactory.getLogger(CredentialStore.class);
	private static HashMap<String, User> credentialsStore = new HashMap<>();
	private static HashMap<String, String> sessionTokenStore = new HashMap<>();

	/**
	 * Store the initial data in the HashMap so that user login function would work
	 * 
	 */
	public void seedCredentialStore() {
		User user = new User();
		user.setUsername("admin");
		user.setPassword("13A95C75B44F95EAD23F47F0BF10667E57B44EC5150180C8A39A39361CF56169");
		credentialsStore.put(user.getUsername(), user);
		logger.debug("Seeded the In-Memory HashMap...");
	}

	/**
	 * Add a user object against the username in the HashMap
	 * 
	 * @param user
	 */
	public void addCredentials(User user) {
		credentialsStore.put(user.getUsername(), user);
		if (user.getToken() != null) {
			sessionTokenStore.put(user.getSessionID(), user.getToken());
		}
	}

	/**
	 * Returns a user object for a given username from the Credentials Store HashMap
	 * 
	 * @param username
	 * @return
	 */
	public User findCredentials(String username) {
		return credentialsStore.get(username);
	}

	/**
	 * Returns the Token for a given session ID from the Token Store HashMap
	 * 
	 * @param sessionId
	 * @return
	 */
	public String findTokenForSession(String sessionId) {
		return sessionTokenStore.get(sessionId);
	}
}
