package com.amarthya.springsecurity.controller;

import com.amarthya.springsecurity.model.JwtResponse;
import com.amarthya.springsecurity.entity.RefreshToken;
import com.amarthya.springsecurity.model.RefreshTokenRequest;
import com.amarthya.springsecurity.entity.Users;
import com.amarthya.springsecurity.repo.UserRepo;
import com.amarthya.springsecurity.service.RefreshTokenService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import  com.amarthya.springsecurity.service.JWTService;
@RestController
public class SpringSecurityController {

    @Autowired
    UserRepo userRepo;
    @Autowired
    AuthenticationManager authenticationManager;
    @Autowired
    JWTService jwtService;
    @Autowired
    private RefreshTokenService refreshTokenService;

    // we can also mention strength (how many rounds hash should be done) & version
    private BCryptPasswordEncoder encoder=new BCryptPasswordEncoder(12);


    @GetMapping("/")
    public String getData(){
        return "Hello Security";
    }

    @GetMapping("/csrftoken")
    public CsrfToken getCSRFToken(HttpServletRequest httpServletRequest){
        return (CsrfToken) httpServletRequest.getAttribute("_csrf");
    }

    @PostMapping("/post")
    public String getDataPost(){
        return "Hello Security post";
    }

    @PostMapping("/register")
    public Users saveData(@RequestBody Users users){
        users.setPassword(encoder.encode(users.getPassword()));
        return userRepo.save(users);
    }

    @PostMapping("/logins")
    public JwtResponse login(@RequestBody Users users){
        return verify(users);

    }

    public JwtResponse verify(Users users){
        // verifying user
        Authentication authentication=authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(users.getUsername(),users.getPassword()));
        if(authentication.isAuthenticated()){
            // generating token after user is verified
           // return jwtService.generateToken(users.getUsername());
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(users.getUsername());
            return JwtResponse.builder()
                    .jwtToken(jwtService.generateToken(users.getUsername()))
                    //providing refresh token also in response
                    .refreshToken(refreshToken.getToken()).build();
        }
        throw new RuntimeException("invalid user request !");
    }

    @PostMapping("/refreshToken")
    public JwtResponse refreshToken(@RequestBody RefreshTokenRequest refreshTokenRequest) {
        return refreshTokenService.findByToken(refreshTokenRequest.getRefreshToken())
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUsers)
                .map(userInfo -> {
                    String jwtToken = jwtService.generateToken(userInfo.getUsername());
                    return JwtResponse.builder()
                            .jwtToken(jwtToken)
                            .refreshToken(refreshTokenRequest.getRefreshToken())
                            .build();
                }).orElseThrow(() -> new RuntimeException(
                        "Refresh token is not in database!"));
    }

}
