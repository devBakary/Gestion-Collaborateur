package com.example.collaborateurgestion.Payload.request;

import lombok.Data;
import lombok.Getter;

import javax.validation.constraints.Size;
import java.util.Set;

@Data
@Getter

public class SignupRequest {

    @Size(min = 3, max = 20)
    private String username;

    @Size(max = 50)
    private String email;

    private Set<String> role;

    @Size(min = 6, max = 40)
    private String password;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Set<String> getRole() {
        return this.role;
    }

    public void setRole(Set<String> role) {
        this.role = role;
    }
}

