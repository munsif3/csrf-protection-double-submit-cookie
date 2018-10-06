package com.munsif.ssd.csrfdoublesubmit.util;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Component;

@Component
@PropertySource("classpath:application.properties")
@ConfigurationProperties
public class ApplicationConfig {

	@Value("${csrfapp.username}")
	private String username;

	@Value("${csrfapp.password}")
	private String password;

	public String getAuthUser() {
		return this.username;
	}

	public void setAuthUser(String username) {
		this.username = username;
	}

	public String getPassword() {
		return this.password;
	}

	public void setPassword(String password) {
		this.password = password;
	}
}
