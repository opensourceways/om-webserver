package com.om.Service;

import cn.authing.core.mgmt.ManagementClient;
import cn.authing.core.types.*;
import com.om.Dao.AuthingUserDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

@Service
public class AuthingService {
    @Autowired
    private Environment env;

    @Autowired
    AuthingUserDao authingUserDao;

    @Autowired
    JwtTokenCreateService jwtTokenCreateService;

    public ResponseEntity authingUserPermission(String community, String userId, String permission) {
        try {
            // 用户是否存在
            User user = authingUserDao.getUser(userId);
            if (user == null) return result(HttpStatus.NOT_FOUND, "user not found", null);

            // 资源权限验证
            String permissionInfo = env.getProperty(community + "." + permission);
            String[] split = permissionInfo.split("->"); // groupCode resourceCode resourceAction
            boolean hasActionPer = authingUserDao.checkUserPermission(userId, split[0], split[1], split[2]);
            ArrayList<String> permissions = new ArrayList<>();
            if (hasActionPer) permissions.add(permission);
//            if (!hasActionPer) return result(HttpStatus.UNAUTHORIZED, "unauthorized", null);

            // 生成token
            String token = jwtTokenCreateService.authingUserToken(userId, permissionInfo);

            // 返回结果
            HashMap<String, Object> userData = new HashMap<>();
            userData.put("id", userId);
            userData.put("token", token);
            userData.put("photo", user.getPhoto());
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
