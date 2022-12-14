package com.example.collaborateurgestion.Controller;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.example.collaborateurgestion.Payload.request.LoginRequest;
import com.example.collaborateurgestion.Payload.request.SignupRequest;
import com.example.collaborateurgestion.Payload.response.MessageResponse;
import com.example.collaborateurgestion.Security.jwt.JwtUtils;
import com.example.collaborateurgestion.Model.ERole;
import com.example.collaborateurgestion.Model.Role;
import com.example.collaborateurgestion.Model.User;
import com.example.collaborateurgestion.Repository.RoleRepository;
import com.example.collaborateurgestion.Repository.UserRepository;
import com.example.collaborateurgestion.Security.Service.UserDetailsImpl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.validation.*;


@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {


    Logger log = LoggerFactory.getLogger(AuthController.class);
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;


    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails);

        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());
        List<String> entite = new ArrayList<>(); entite.add("ROLE_USER");
        if (roles.equals(entite)) {
            return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
                    .body("BIENVENU USER");
        }
        else {
            return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
                    .body("BIENVENU ADMIN");
        }

    }


    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/signup") public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (

                userRepository.existsByUsername(signUpRequest.getUsername())) {
            log.info("ce nom d'utilisateur est d??ja pris");
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: nom d'utilisateur est d??ja pris!"));
        }

        if (
                userRepository.existsByEmail(signUpRequest.getEmail())) {
            log.info("cet email est d??ja pris");
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: cet email est d??ja pris!")
                    );

        }

        // Create new user's account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);

                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

}
