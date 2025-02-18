/* This project is licensed under the Mulan PSL v2.
 You can use this software according to the terms and conditions of the Mulan PSL v2.
 You may obtain a copy of Mulan PSL v2 at:
     http://license.coscl.org.cn/MulanPSL2
 THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 PURPOSE.
 See the Mulan PSL v2 for more details.
 Create: 2024
*/

package com.om.aop;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.Signature;
import org.aspectj.lang.reflect.SourceLocation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;

public class ManagementOperationLogAOPTest {
    private ManagementOperationLogAOP managementOperationLogAOPUnderTest;

    @BeforeEach
    public void setUp() {
        managementOperationLogAOPUnderTest = new ManagementOperationLogAOP();
        ReflectionTestUtils.setField(managementOperationLogAOPUnderTest, "request", new MockHttpServletRequest());
        ReflectionTestUtils.setField(managementOperationLogAOPUnderTest, "response", new MockHttpServletResponse());
    }

    @Test
    public void testPointcut() {
        managementOperationLogAOPUnderTest.pointcut();
    }

    @Test
    public void testAfterReturning() {
        final JoinPoint joinPoint = new JoinPoint() {
            @Override
            public String toShortString() {
                return null;
            }

            @Override
            public String toLongString() {
                return null;
            }

            @Override
            public Object getThis() {
                return null;
            }

            @Override
            public Object getTarget() {
                return null;
            }

            @Override
            public Object[] getArgs() {
                return new Object[0];
            }

            @Override
            public Signature getSignature() {
                Signature signature = new Signature() {
                    @Override
                    public String toShortString() {
                        return null;
                    }

                    @Override
                    public String toLongString() {
                        return null;
                    }

                    @Override
                    public String getName() {
                        return "testName";
                    }

                    @Override
                    public int getModifiers() {
                        return 0;
                    }

                    @Override
                    public Class getDeclaringType() {
                        return null;
                    }

                    @Override
                    public String getDeclaringTypeName() {
                        return "testDeclaringTypeName";
                    }
                };
                return signature;
            }

            @Override
            public SourceLocation getSourceLocation() {
                return null;
            }

            @Override
            public String getKind() {
                return null;
            }

            @Override
            public StaticPart getStaticPart() {
                return null;
            }
        };
        managementOperationLogAOPUnderTest.afterReturning(joinPoint, "returnObject");
    }
}
