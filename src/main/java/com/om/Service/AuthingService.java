package com.om.Service;

import cn.authing.core.types.User;
import com.om.Dao.AuthingUserDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

@Service
public class AuthingService {
    @Autowired
    private Environment env;

    @Autowired
    AuthingUserDao authingUserDao;

    @Autowired
    JwtTokenCreateService jwtTokenCreateService;

    public ResponseEntity authingUserPermission(String community, String code, String permission) {
        try {
            // 通过code获取access_token，再通过access_token获取用户
            Map user = authingUserDao.getUserInfoByAccessToken(code);
            if (user == null) return result(HttpStatus.UNAUTHORIZED, "user not found", null);
            String userId = user.get("sub").toString();

            // 资源权限验证
            String permissionInfo = env.getProperty(community + "." + permission);
            String[] split = permissionInfo.split("->"); // groupCode resourceCode resourceAction
            boolean hasActionPer = authingUserDao.checkUserPermission(userId, split[0], split[1], split[2]);
            ArrayList<String> permissions = new ArrayList<>();
            if (hasActionPer) permissions.add(permission);

            // 生成token
            String token = jwtTokenCreateService.authingUserToken(userId, permissionInfo);

            // 返回结果
            HashMap<String, Object> userData = new HashMap<>();
            userData.put("id", userId);
            userData.put("token", token);
            userData.put("photo", user.get("picture").toString());
            userData.put("permissions", permissions);
            return result(HttpStatus.OK, "success", userData);
        } catch (Exception e) {
            e.printStackTrace();
            return result(HttpStatus.UNAUTHORIZED, "unauthorized", null);
        }
    }

    private ResponseEntity result(HttpStatus status, String msg, Object data) {
        HashMap<String, Object> res = new HashMap<>();
        res.put("code", status.value());
        res.put("data", data);
        res.put("msg", msg);
        return new ResponseEntity<>(res, status);
    }

}
