package com.om.Service.inter;

import org.springframework.http.ResponseEntity;

public interface ThirdPartyServiceInter {

    ResponseEntity<?> thirdPartyList(String clientId);
    
    ResponseEntity<?> thirdPartyAuthorize(String clientId, String connId);

    ResponseEntity<?> thirdPartyCallback(String connId, String code, String state);

    // ResponseEntity<?> thirdPartyCreateUser();

    // ResponseEntity<?> thirdPartyLink();

    // ResponseEntity<?> thirdPartyLinkInUserCenter();

    // ResponseEntity<?> thirdPartyUnlinkInUserCenter();

}
