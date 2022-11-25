package com.example.collaborateurgestion.Repository;

import com.example.collaborateurgestion.Model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;


public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);

    //Optional<User> modifier(User user);

   // void supprimer(Long id);

    Boolean existsByUsername(String username);

    Boolean existsByEmail(String email);
}
