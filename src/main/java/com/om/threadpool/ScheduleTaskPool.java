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

package com.om.threadpool;

import jakarta.annotation.PreDestroy;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;
import org.springframework.stereotype.Component;

@Component
public class ScheduleTaskPool {
    /**
     * 线程池任务调度器.
     */
    private ThreadPoolTaskScheduler threadPoolTaskScheduler;

    /**
     * Bean定义：SR-Task-SchedulePool，用于获取任务调度器.
     *
     * @return ThreadPoolTaskScheduler 对象
     */
    @Bean("SR-Task-SchedulePool")
    public ThreadPoolTaskScheduler getScheduleTask() {
        ThreadPoolTaskScheduler executor = new ThreadPoolTaskScheduler();
        executor.setPoolSize(3);
        executor.setThreadNamePrefix("Task-");
        executor.setWaitForTasksToCompleteOnShutdown(false);
        executor.setAwaitTerminationSeconds(10);
        executor.setRemoveOnCancelPolicy(true);
        this.threadPoolTaskScheduler = executor;
        return executor;
    }

    @PreDestroy
    private void destroy() {
        if (threadPoolTaskScheduler != null) {
            threadPoolTaskScheduler.shutdown();
            threadPoolTaskScheduler = null;
        }
    }
}
