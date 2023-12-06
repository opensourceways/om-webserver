package com.om.Service.inter;

import com.om.Vo.dto.OidcAuthorize;
import org.springframework.http.ResponseEntity;

public interface OidcServiceInter {

    ResponseEntity<?> oidcAuthorize(OidcAuthorize oidcAuthorize);

}
