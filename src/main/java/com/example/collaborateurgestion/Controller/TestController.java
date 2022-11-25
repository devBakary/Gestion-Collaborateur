package com.example.collaborateurgestion.Controller;

import com.example.collaborateurgestion.Model.User;
import com.example.collaborateurgestion.Repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/test")
public class TestController {


    @Autowired
    UserRepository userRepository;

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public String userAccess() {
        return "User Content.";
    }

   /* @GetMapping("/mod")
    @PreAuthorize("hasRole('MODERATOR')")
    public String moderatorAccess() {
        return "Moderator Board.";
    }*/

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminAccess() {
        return "Admin Board.";
    }

    @GetMapping("/afficher")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public List<User> afficher() {
        return userRepository.findAll();
    }


    @PutMapping("/modifier/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public User modifier(@RequestBody User user, @PathVariable Long id){
        User userUpdate = userRepository.findById(id).get();
        userUpdate.setUsername(user.getUsername());
        userUpdate.setPassword(user.getPassword());
        userUpdate.setEmail(user.getEmail());
        userUpdate.setRoles(user.getRoles());
        return userRepository.saveAndFlush(user);
    }

    @DeleteMapping("/effacer/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public String supprimer(@PathVariable Long id){
        userRepository.deleteById(id);
        return "supprimé avec succès !";
    }


}
