package com.munsif.ssd.csrfdoublesubmit.model;

/**
 * Acts as the model for the state changing operation
 * 
 * @author munsif
 *
 */
public class Blog {

	private String blogname;
	private String blogbody;
	private String token;

	public String getBlogname() {
		return blogname;
	}

	public void setBlogname(String blogname) {
		this.blogname = blogname;
	}

	public String getBlogbody() {
		return blogbody;
	}

	public void setBlogbody(String blogbody) {
		this.blogbody = blogbody;
	}

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}

	@Override
	public String toString() {
		return "Blog [blogname=" + blogname + ", blogbody=" + blogbody + ", token=" + token + "]";
	}
}
