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

package com.om.modules;

/**
 * 服务器错误异常类.
 */
public class ServerErrorException extends Exception {
    /**
     * 构造一个新的 ServerErrorException 实例.
     */
    public ServerErrorException() {
        super();
    }

    /**
     * 构造一个新的 ServerErrorException 实例，其中包含仅指定消息的详细信息.
     *
     * @param message 详细信息字符串
     */
    public ServerErrorException(String message) {
        super(message);
    }
}
