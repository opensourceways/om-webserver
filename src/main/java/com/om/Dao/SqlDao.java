package com.om.Dao;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;

@Repository
public class SqlDao {
    @Value("${mysql.url}")
    String mysqlUrl;

    @Value("${mysql.user}")
    String user;

    @Value("${mysql.password}")
    String password;

    @Value("${mysql.driver}")
    String JDBC_DRIVER;

    public static Connection conn;

    @PostConstruct
    public void init() {
        conn = dbCon();
    }

    public ArrayList<HashMap<String, String>> getUserData(String sql) {
        ArrayList<HashMap<String, String>> res = new ArrayList<>();
        try {
            Statement statement = conn.createStatement();
            ResultSet rs = statement.executeQuery(sql);
            while (rs.next()) {
                String username = rs.getString("username");
                String photo = rs.getString("photo");
                HashMap<String, String> user = new HashMap<String, String>();
                user.put("username", username);
                user.put("photo", photo);
                
                res.add(user);
            }
            rs.close();

        } catch (SQLException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return res;
    }

    public Connection dbCon() {
        Connection con = null;
        try {
            Class.forName(JDBC_DRIVER);
            con = DriverManager.getConnection(mysqlUrl, user, password);
            System.out.println("connect mysql succeed.");
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("connect mysql failed.");
        }
        return con;
    }
}
