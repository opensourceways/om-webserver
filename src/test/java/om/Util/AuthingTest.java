package om.Util;

import cn.authing.core.mgmt.ManagementClient;
import cn.authing.core.types.*;
import org.junit.jupiter.params.shadow.com.univocity.parsers.csv.CsvWriter;
import org.junit.jupiter.params.shadow.com.univocity.parsers.csv.CsvWriterSettings;

import java.io.File;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.List;

public class AuthingTest {
    public static void main(String[] args) {
        try {
            authingUserExport();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // 导出authing用户 (导出的用户信息自己修改)
    public static void authingUserExport() throws Exception {
        // 需要导出的用户username
        /*String[] users = new String[]{"xxx", "xxx"};
        List<String> filterUsers = Arrays.asList(users);*/

        // csvWriter，headers(自己修改)
        CsvWriter csvWriter = new CsvWriter(new File("D:\\xxx.csv"), Charset.forName("GBK"), new CsvWriterSettings());
        String[] headers = {"signedUp", "username", "nickname", "giteeLogin"};
        csvWriter.writeHeaders(headers);

        // （用户池id和secret自己修改）
        ManagementClient managementClient = new ManagementClient("xxx", "xxx");
        int page = 1;
        while (page <= 1000) {
            UsersParam usersParam = new UsersParam(page, 200, SortByEnum.CREATEDAT_ASC, true);
            PaginatedUsers execute = managementClient.users().list(usersParam).execute();
            List<User> list = execute.getList();
            if (list.isEmpty()) break;
            for (User user : list) {
                /*// 1、过滤username用户导出（字段自己修改，跟csv headers对应）
                if (!filterUsers.contains(user.getUsername())) continue;
                String[] strings = {user.getUsername(), user.getEmail()};
                csvWriter.writeRow(strings);
                csvWriter.flush();*/

                // 2、有绑定gitee的用户导出
                List<UserCustomData> customData = user.getCustomData();
                if (customData == null) continue;
                for (UserCustomData customDatum : customData) {
                    if (!customDatum.getKey().equals("giteeLogin")) continue;
                    String[] giteeUsers = {user.getSignedUp(), user.getUsername(), user.getNickname(), customDatum.getValue()};
                    csvWriter.writeRow(giteeUsers);
                    csvWriter.flush();
                }
            }
            System.out.println("*** finish page: " + page);
            page += 1;
        }
        csvWriter.flush();
        csvWriter.close();
    }
}
