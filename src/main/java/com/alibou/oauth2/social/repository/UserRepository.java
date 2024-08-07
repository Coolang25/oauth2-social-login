package com.alibou.oauth2.social.repository;

import com.alibou.oauth2.social.domain.User;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface UserRepository extends CrudRepository<User, Long> {
	Optional<User> getUserByEmail(String email);

//	@Query("SELECT u FROM User u WHERE u.username = :username")
//	public User getUserByUsername(@Param("username") String username);
}
