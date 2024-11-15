package com.amarthya.springsecurity.model;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import lombok.Data;

@Data
@Entity
public class Users {

    @Id
    private String id;
    private String username;
    private String password;


}
