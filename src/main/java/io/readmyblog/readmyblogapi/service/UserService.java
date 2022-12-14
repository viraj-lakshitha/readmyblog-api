package io.readmyblog.readmyblogapi.service;

import io.readmyblog.readmyblogapi.core.model.User;
import io.readmyblog.readmyblogapi.core.vo.AuthUserVO;
import io.readmyblog.readmyblogapi.exception.ResourceNotFoundException;
import io.readmyblog.readmyblogapi.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    public AuthUserVO getCurrentUser(String userId) {
        User user = userRepository.findById(userId).orElseThrow(ResourceNotFoundException::new);
        return new AuthUserVO(user.getId(), user.getName(), user.getUserName(), user.getEmail(), user.getImageUrl(), user.getProvider(), user.getRole(), user.getIsActive());
    }

}