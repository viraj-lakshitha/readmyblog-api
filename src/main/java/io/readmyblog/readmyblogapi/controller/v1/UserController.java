package io.readmyblog.readmyblogapi.controller.v1;

import io.readmyblog.readmyblogapi.auth.CurrentUser;
import io.readmyblog.readmyblogapi.auth.UserPrincipal;
import io.readmyblog.readmyblogapi.core.vo.AuthUserVO;
import io.readmyblog.readmyblogapi.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("/v1/users")
public class UserController {

    @Autowired
    private UserService userService;

    private PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @GetMapping("/me")
    public AuthUserVO getCurrentUser(@CurrentUser UserPrincipal userPrincipal) {
        return userService.getCurrentUser(userPrincipal.getId());
    }
}
