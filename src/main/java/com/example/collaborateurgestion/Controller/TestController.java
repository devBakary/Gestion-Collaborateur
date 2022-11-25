package com.example.collaborateurgestion.Controller;

import com.example.collaborateurgestion.Model.User;
import com.example.collaborateurgestion.Repository.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.List;
import java.util.Map;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
//@RequestMapping("/api/test")
@AllArgsConstructor
public class TestController {

    private final OAuth2AuthorizedClientService authorizedClientService;

    @Autowired
    UserRepository userRepository;


    @GetMapping("/user")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public String userAccess() {
        return "User Content.";
    }

    @GetMapping("/*")
    public String getUserInfo(Principal user) {
        StringBuffer userInfo= new StringBuffer();
        if (user instanceof UsernamePasswordAuthenticationToken){
            userInfo.append(getUsernamePasswordLoginInfo(user));
        }
        else if (user instanceof OAuth2AuthenticationToken){
            userInfo.append(getOauth2LoginInfo(user));
        }
        return userInfo.toString();

    }

    private StringBuffer getOauth2LoginInfo(Principal user){
        StringBuffer protectedInfo = new StringBuffer();
        OAuth2AuthenticationToken authToken = ((OAuth2AuthenticationToken) user);

        OAuth2AuthorizedClient authClient = this.authorizedClientService
                .loadAuthorizedClient(authToken.getAuthorizedClientRegistrationId(), authToken.getName());
        Map<String, Object> userDetails = ((DefaultOAuth2User) authToken.getPrincipal()).getAttributes();

        String userToken = authClient.getAccessToken().getTokenValue();
        protectedInfo.append("bienvenu, " + userDetails.get("name")+"<br><br>");
        protectedInfo.append("email, " + userDetails.get("email")+"<br><br>");
        protectedInfo.append("Access Token, " + userToken +"<br><br>");
        return protectedInfo;
    }

    private StringBuffer getUsernamePasswordLoginInfo(Principal user) {
        StringBuffer usernameInfo = new StringBuffer();
        UsernamePasswordAuthenticationToken token = ((UsernamePasswordAuthenticationToken) user);
        if (token.isAuthenticated()){
            User u =(User) token.getPrincipal();
            usernameInfo.append("bienvenu, " + u.getUsername());
        }
        else {
            usernameInfo.append("Na");
        }

        return usernameInfo;
    }


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
