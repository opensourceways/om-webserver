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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
public class LimitUtil {
    /**
     * 自动注入 RedisDao 对象.
     */
    @Autowired
    private RedisDao redisDao;

    /**
     * 自动注入 Environment 环境对象.
     */
    @Autowired
    private Environment env;


    /**
     * 日志记录器，用于记录 LimitUtil 类的日志信息.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(LimitUtil.class);

    /**
     * 初始化登录失败计数器.
     *
     * @param account 账户信息
     * @return LoginFailCounter 对象
     */
    public LoginFailCounter initLoginFailCounter(String account) {
        String loginFailAccountCountKey = account + Constant.LOGIN_COUNT;
        return new LoginFailCounter()
                .setAccount(account)
                .setAccountKey(loginFailAccountCountKey)
                .setAccountCount(redisDao.getLoginErrorCount(loginFailAccountCountKey))
                .setLimitCount(Integer.parseInt(env.getProperty(
                        "login.error.limit.count", Constant.LOGIN_ERROR_LIMIT)))
                .setLimitSeconds(Long.parseLong(env.getProperty(
                        "login.error.limit.seconds", Constant.DEFAULT_EXPIRE_SECOND)));
    }

    /**
     * 检查是否需要验证码.
     *
     * @param failCounter 登录失败计数器
     * @return 包含是否需要验证码信息的 HashMap
     */
    public HashMap<String, Boolean> isNeedCaptcha(LoginFailCounter failCounter) {
        HashMap<String, Boolean> data = new HashMap<>();
        data.put(Constant.NEED_CAPTCHA_VERIFICATION, false);
        int needCaptchaLimit =
                Integer.parseInt(env.getProperty(
                        "need.captcha.limit.count", Constant.NEED_CAPTCHA_VERIFICATION_LIMIT));
        if (failCounter.getAccountCount() >= needCaptchaLimit) {
            data.put(Constant.NEED_CAPTCHA_VERIFICATION, true);
        }
        return data;
    }

    /**
     * 处理登录失败事件.
     *
     * @param failCounter 登录失败计数器
     * @return 包含登录失败信息的 Map
     */
    public Map<String, Boolean> loginFail(LoginFailCounter failCounter) {
        failCounter.setAccountCount(failCounter.getAccountCount() + 1);
        redisDao.set(failCounter.getAccountKey(), String.valueOf(failCounter.getAccountCount()),
                failCounter.getLimitSeconds());

        if (failCounter.getAccountCount() >= failCounter.getLimitCount()) {
            LOGGER.info(String.format("Account %s is locked until %s seconds later",
                    failCounter.getAccount(), failCounter.getLimitSeconds()));
        }

        return isNeedCaptcha(failCounter);
    }
}
