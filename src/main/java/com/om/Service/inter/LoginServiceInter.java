package com.om.Service.inter;

import com.om.Vo.dto.LoginParam;
import org.springframework.http.ResponseEntity;

public interface LoginServiceInter {
    ResponseEntity<?> appVerify(String clientId, String redirectUri);

    ResponseEntity<?> userLogin(LoginParam loginParam);

    ResponseEntity<?> userLogout(String clientId, String token);

    ResponseEntity<?> refreshUser(String clientId, String token);

    ResponseEntity<?> personalCenterUserInfo(String clientId, String token);
}
