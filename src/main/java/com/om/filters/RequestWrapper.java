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

package com.om.filters;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import java.io.*;
import java.nio.charset.Charset;
import java.util.Map;

/**
 * 包装HttpServletRequest，目的是让其输入流可重复读
 * <p>
 * 1、将输入流里面的数据存储到body。
 * 2、重写getInputStream方法，每次都从body读数据
 */
public class RequestWrapper extends HttpServletRequestWrapper {
    // 存储请求body数据
    private final byte[] body;

    /**
     * 将输入流里面的数据存储到body
     *
     * @param request request
     */
    public RequestWrapper(HttpServletRequest request) throws IOException {
        super(request);

        // parameters回写
        Map<String, String[]> parameterMap = request.getParameterMap();
        for (Map.Entry<String, String[]> entry : parameterMap.entrySet()) {
            request.setAttribute(entry.getKey(), entry.getValue());
        }

        StringBuilder sb = new StringBuilder();
        BufferedReader reader = null;

        // 将inputStream里的数据读取出来
        try {
            InputStream inputStream = request.getInputStream();
            reader = new BufferedReader(
                    new InputStreamReader(inputStream, Charset.defaultCharset()));
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException ignored) {

                }
            }
        }

        // 存储body的数据
        body = sb.toString().getBytes(Charset.defaultCharset());
    }

    /**
     * 每次getInputStream()都根据body创建新的输入流
     *
     * @return ServletInputStream
     */
    @Override
    public ServletInputStream getInputStream() throws IOException {
        final ByteArrayInputStream inputStream = new ByteArrayInputStream(body);
        return new ServletInputStream() {
            @Override
            public boolean isFinished() {
                return false;
            }

            @Override
            public boolean isReady() {
                return false;
            }

            @Override
            public void setReadListener(ReadListener readListener) {
            }

            public int read() throws IOException {
                return inputStream.read();
            }
        };
    }

    /**
     * 每次getReader()都根据body创建新的输入流
     *
     * @return BufferedReader
     */
    @Override
    public BufferedReader getReader() throws IOException {
        return new BufferedReader(new InputStreamReader(this.getInputStream()));
    }
}
