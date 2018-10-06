package com.munsif.ssd.csrfdoublesubmit;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import com.munsif.ssd.csrfdoublesubmit.model.CredentialStore;

@SpringBootApplication
public class CsrfdoublesubmitApplication {

	public static void main(String[] args) {
		SpringApplication.run(CsrfdoublesubmitApplication.class, args);
		
		// Initial seeding of the credentials store HashMap
		new CredentialStore().seedCredentialStore();
	}
}
