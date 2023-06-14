/* This project is licensed under the Mulan PSL v2.
 You can use this software according to the terms and conditions of the Mulan PSL v2.
 You may obtain a copy of Mulan PSL v2 at:
     http://license.coscl.org.cn/MulanPSL2
 THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 PURPOSE.
 See the Mulan PSL v2 for more details.
 Create: 2023
*/

package com.om.Utils;

import com.om.Dao.RedisDao;
import com.om.Modules.LoginFailCounter;
import com.om.Result.Constant;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
public class LimitUtil {
    @Autowired
    RedisDao redisDao;

    @Autowired
    Environment env;

    public LoginFailCounter initLoginFailCounter(String account) {
        String loginFailAccountCountKey = account + Constant.LOGIN_COUNT;
        return new LoginFailCounter()
                .setAccount(account)
                .setAccountKey(loginFailAccountCountKey)
                .setAccountCount(redisDao.getLoginErrorCount(loginFailAccountCountKey))
                .setLimitCount(
                        Integer.parseInt(env.getProperty("login.error.limit.count", Constant.LOGIN_ERROR_LIMIT)))
                .setLimitSeconds(
                        Long.parseLong(env.getProperty("login.error.limit.seconds", Constant.DEFAULT_EXPIRE_SECOND)));
    }

    public HashMap<String, Boolean> isNeedCaptcha(LoginFailCounter failCounter) {
        HashMap<String, Boolean> data = new HashMap<>();
        data.put(Constant.NEED_CAPTCHA_VERIFICATION, false);
        int needCaptchaLimit =
                Integer.parseInt(env.getProperty("need.captcha.limit.count", Constant.NEED_CAPTCHA_VERIFICATION_LIMIT));
        if (failCounter.getAccountCount() >= needCaptchaLimit) {
            data.put(Constant.NEED_CAPTCHA_VERIFICATION, true);
        }
        return data;
    }

    public Map<String, Boolean> loginFail(LoginFailCounter failCounter) {
        failCounter.setAccountCount(failCounter.getAccountCount() + 1);
        redisDao.set(failCounter.getAccountKey(), String.valueOf(failCounter.getAccountCount()),
                failCounter.getLimitSeconds());

        return isNeedCaptcha(failCounter);
    }
}
