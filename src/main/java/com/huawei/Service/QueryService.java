package com.huawei.Service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.huawei.Dao.QueryDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ExecutionException;

/**
 * @author zhxia
 * @date 2020/10/22 11:40
 */
@Service
public class QueryService {
    @Autowired
    QueryDao queryDao;

    public String queryContributors(String community) throws KeyManagementException, NoSuchAlgorithmException {
        return queryDao.queryContributors(community);
    }


    public String querySigs(String community) throws InterruptedException, ExecutionException, NoSuchAlgorithmException, KeyManagementException, JsonProcessingException {
        return queryDao.querySigs(community);
    }

    public String queryUsers( String community) throws InterruptedException, ExecutionException, JsonProcessingException, NoSuchAlgorithmException, KeyManagementException {
        return queryDao.queryUsers(community);
    }


    public String queryNoticeusers( String community) throws InterruptedException, ExecutionException, NoSuchAlgorithmException, KeyManagementException, JsonProcessingException {
        return queryDao.queryNoticeusers(community);
    }


    public String queryModulenums(String community) throws InterruptedException, ExecutionException, NoSuchAlgorithmException, KeyManagementException, JsonProcessingException {
        return queryDao.queryModulenums(community);
    }

    public String queryBusinessOsv(String community) throws InterruptedException, ExecutionException, NoSuchAlgorithmException, KeyManagementException, JsonProcessingException {
        return queryDao.queryBusinessOsv(community);
    }

    public String queryAll( String community) throws InterruptedException, ExecutionException, JsonProcessingException, NoSuchAlgorithmException, KeyManagementException {
        return queryDao.queryAll(community);
    }

}

