/* This project is licensed under the Mulan PSL v2.
 You can use this software according to the terms and conditions of the Mulan PSL v2.
 You may obtain a copy of Mulan PSL v2 at:
     http://license.coscl.org.cn/MulanPSL2
 THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 PURPOSE.
 See the Mulan PSL v2 for more details.
 Create: 2022
*/

package com.om.Dao;

import com.obs.services.ObsClient;
import com.obs.services.model.ObsObject;
import com.obs.services.model.PutObjectRequest;
import java.io.File;
import java.io.InputStream;
import javax.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;

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
