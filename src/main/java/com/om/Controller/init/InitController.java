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

package com.om.Controller.init;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.web.bind.annotation.RestController;

import com.om.Utils.CommonUtil;


@RestController
public class InitController implements ApplicationRunner{

    private static final Logger log =  LoggerFactory.getLogger(InitController.class);

    @Override
    public void run(ApplicationArguments args) throws Exception {
        String applicationPath = System.getenv("APPLICATION_PATH");
        if (StringUtils.isBlank(applicationPath)) {
            log.info("Delete application fail, file not found");
            return;
        }
        if (CommonUtil.deleteFile(applicationPath)) {
            log.info("Delete application success");
        } else {
            log.info("Delete application fail");
        }
    }

}