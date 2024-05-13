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

package com.om.Modules;

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

    /**
     * 构造一个新的 ServerErrorException 实例，其中包含指定消息和原因的详细信息.
     *
     * @param message 详细信息字符串
     * @param cause   引起此异常的 Throwable
     */
    public ServerErrorException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * 构造一个新的 ServerErrorException 实例，其中包含指定的原因.
     *
     * @param cause 引起此异常的 Throwable
     */
    public ServerErrorException(Throwable cause) {
        super(cause);
    }

    /**
     * 构造一个新的 ServerErrorException 实例，其中包含指定消息、原因、启用或禁用抑制以及堆栈跟踪是否可写的详细信息.
     *
     * @param message            详细信息字符串
     * @param cause              引起此异常的 Throwable
     * @param enableSuppression  是否启用抑制
     * @param writableStackTrace 堆栈跟踪是否可写
     */
    public ServerErrorException(String message, Throwable cause,
                                boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

}
