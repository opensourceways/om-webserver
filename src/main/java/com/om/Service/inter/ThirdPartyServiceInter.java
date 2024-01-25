package com.om.Service.inter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.ResponseEntity;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public interface ThirdPartyServiceInter {

    ResponseEntity<?> thirdPartyList(String clientId);

    ResponseEntity<?> thirdPartyAuthorize(String clientId, String connId);

    ResponseEntity<?> thirdPartyCallback(String connId, String code, String state, String appId);

    ResponseEntity<?> thirdPartyCreateUser(String registerToken, String appId, String state);

}
