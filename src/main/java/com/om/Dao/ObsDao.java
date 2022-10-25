package com.om.Dao;

import com.obs.services.ObsClient;
import com.obs.services.model.ObsObject;
import com.obs.services.model.PutObjectRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;
import javax.annotation.PostConstruct;
import java.io.File;
import java.io.InputStream;

@Repository
public class ObsDao {
    @Value("${ip.location.ak}")
    String IPAk;

    @Value("${ip.location.sk}")
    String IPSk;

    @Value("${ip.location.endpoint}")
    String IPEndpoint;

    @Value("${ip.location.bucket.name}")
    String IPBucket;

    @Value("${ip.database.path}")
    String localPath;

    @Value("${ip.location.object.key}")
    String IPObjectKey;

    public static ObsClient obsClient;

    @PostConstruct
    public void init() {
        obsClient = new ObsClient(IPAk, IPSk, IPEndpoint);      
    }

    public void putData() {
        PutObjectRequest request = new PutObjectRequest();
        request.setBucketName(IPBucket);
        request.setObjectKey(IPObjectKey);
        request.setFile(new File(localPath));
        obsClient.putObject(request);
    }

    public InputStream getData() {
        ObsObject object = obsClient.getObject(IPBucket, IPObjectKey);
        InputStream res = object.getObjectContent();
        return res;
    }
}
