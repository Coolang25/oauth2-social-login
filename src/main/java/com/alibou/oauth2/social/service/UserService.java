package com.alibou.oauth2.social.service;

import com.alibou.oauth2.social.domain.User;
import com.alibou.oauth2.social.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {

	@Autowired
	private UserRepository repo;
	
	public void saveUser(String email) {
		Optional<User> existUser = repo.getUserByEmail(email);
		
		if (existUser.isEmpty()) {
			User newUser = new User();
			newUser.setEmail(email);
			
			repo.save(newUser);
			
			System.out.println("Created new user: " + email);
		}
		
	}
	
}
