package com.om.Service.impl;

import java.util.HashMap;
import java.util.List;
import java.util.UUID;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.om.Dao.RedisDao;
import com.om.Dao.oneId.OneIdEntity;
import com.om.Dao.oneId.OneIdThirdPartyDao;
import com.om.Modules.MessageCodeConfig;
import com.om.Result.Result;
import com.om.Service.inter.ThirdPartyServiceInter;

@Service
public class ThirdPartyServiceImpl implements ThirdPartyServiceInter {
    
    private static final Logger logger = LoggerFactory.getLogger(OidcServiceImplOneId.class);

    @Autowired
    private Environment env;

    @Autowired
    private OneIdThirdPartyDao oneIdThirdPartyDao;

    @Autowired
    private RedisDao redisDao;

    @Override
    public ResponseEntity<?> thirdPartyList(String clientId) {
        try {
            List<OneIdEntity.ThirdPartyClient> sources = oneIdThirdPartyDao.getAllClientsByAppId(clientId);

            if (sources == null) {
                return Result.setResult(HttpStatus.NOT_FOUND, MessageCodeConfig.E00066,  null, null, null);
            }

            HashMap<String, String> sourceIds = new HashMap<>();
            for (OneIdEntity.ThirdPartyClient source : sources) {
                sourceIds.put(source.getName(), source.getId());
            }

            return Result.setResult(HttpStatus.OK, MessageCodeConfig.S0001, null, sourceIds, null);
        } catch (Exception e) {
            logger.error(e.getMessage());
            return Result.setResult(HttpStatus.INTERNAL_SERVER_ERROR, null,  "Internal Server Error", null, null);
        }
    }

    @Override
    public ResponseEntity<?> thirdPartyAuthorize(String clientId, String connId) {
        try {
            OneIdEntity.ThirdPartyClient source = oneIdThirdPartyDao.getClientByAssociation(clientId, connId);

            if (source == null) {
                return Result.setResult(HttpStatus.NOT_FOUND, MessageCodeConfig.E00066,  null, null, null);
            }
            
            String thirdPartyLoginPage = String.format("%s?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s",
                source.getAuthorizeUrl(),
                source.getClientId(),
                String.format(env.getProperty("external.callback.url"), source.getId()),
                source.getScopes(), 
                generateState());

            return ResponseEntity.status(HttpStatus.MOVED_PERMANENTLY).header(HttpHeaders.LOCATION, thirdPartyLoginPage).build();
        } catch (Exception e) {
            logger.error(e.getMessage());
            return Result.setResult(HttpStatus.INTERNAL_SERVER_ERROR, null,  "Internal Server Error", null, null);
        }
    }

    @Override
    public ResponseEntity<?> thirdPartyCallback(String connId, String code, String state) {
        try {
            // check state
            if (redisDao.get(state) == null) {
                return Result.setResult(HttpStatus.BAD_REQUEST, MessageCodeConfig.E00012,  null, null, null);
            }

            OneIdEntity.ThirdPartyClient source = oneIdThirdPartyDao.getClientById(connId);

            if (source == null) {
                return Result.setResult(HttpStatus.NOT_FOUND, MessageCodeConfig.E00066,  null, null, null);
            }

            // code换token
            String body = String.format("{\"client_id\": \"%s\", \"client_secret\": \"%s\", " +
                "\"code\": \"%s\", \"redirect_uri\": \"%s\", \"grant_type\": \"authorization_code\"}", 
                source.getClientId(), source.getClientSecret(), code, 
                String.format(env.getProperty("external.callback.url"), source.getId()));
            HttpResponse<JsonNode> response = Unirest.post(source.getTokenUrl())
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .body(body)
                .asJson();

            String accessToken = null;
            if (response.getStatus() == 200) {
                accessToken = response.getBody().getObject().getString("access_token");
            } else {
                logger.error("thirdPartyCallback err: " + response.getBody().toString());
                return Result.setResult(HttpStatus.INTERNAL_SERVER_ERROR, null,  "Internal Server Error", null, null);
            }

            // token获取用户信息
            HttpResponse<JsonNode> responseUser = Unirest.get(source.getUserUrl())
                .header("Accept", "application/json")
                .header("Authorization", "Bearer " + accessToken)
                .asJson();

            JSONObject user = null;
            if (responseUser.getStatus() == 200) {
                user = responseUser.getBody().getObject();
            } else {
                logger.error("thirdPartyCallback err: " + responseUser.getBody().toString());
                return Result.setResult(HttpStatus.INTERNAL_SERVER_ERROR, null,  "Internal Server Error", null, null);
            }

            HashMap<String, String> userMap = new HashMap<>();
            userMap.put("username", user.getString("login"));
            return Result.setResult(HttpStatus.OK, MessageCodeConfig.S0001, null, userMap, null);
        } catch (Exception e) {
            logger.error(e.getMessage());
            return Result.setResult(HttpStatus.INTERNAL_SERVER_ERROR, null,  "Internal Server Error", null, null);
        }
    }

    private String generateState() {
        String state = UUID.randomUUID().toString().replaceAll("-", "");
        long expireSeconds = Long.parseLong("300");
        redisDao.set(state, "valid", expireSeconds);

        return state;
    }
}
