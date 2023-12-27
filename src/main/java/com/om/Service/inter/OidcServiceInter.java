package com.om.Service.inter;

import com.om.Vo.dto.LoginParam;
import com.om.Vo.dto.OidcAuth;
import com.om.Vo.dto.OidcAuthorize;
import com.om.Vo.dto.OidcToken;
import org.springframework.http.ResponseEntity;

public interface OidcServiceInter {

    ResponseEntity<?> oidcAuthorize(OidcAuthorize oidcAuthorize);

    ResponseEntity<?> oidcAuth(String token, OidcAuth oidcAuth);

    ResponseEntity<?> oidcToken(OidcToken oidcToken);

    ResponseEntity<?> oidcUser(String token);

    ResponseEntity<?> appVerify(String clientId, String redirectUri);

    ResponseEntity<?> userLogin(LoginParam loginParam);

    ResponseEntity<?> refreshUser(String clientId, String token);

}
