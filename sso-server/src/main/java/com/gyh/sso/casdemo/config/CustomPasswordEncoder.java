package com.gyh.sso.casdemo.config;

import com.gyh.sso.casdemo.utils.MD5Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;

public class CustomPasswordEncoder implements PasswordEncoder {

    private final static Logger LOG = LoggerFactory.getLogger(CustomPasswordEncoder.class);

    public String encode(CharSequence password) {
        try {
            //给数据进行md5加密
            LOG.error("=======================password: " + password + "=================================");
            String salt = MD5Utils.getSalt();
            LOG.error("=======================salt: " + salt + "=================================");
            return MD5Utils.getSaltMD5(password.toString(), salt);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 调用这个方法来判断密码是否匹配
     */
    /**
     *
     * @param rawPassword 前台传入密码
     * @param encodePassword 数据库密码
     * @return
     */
    public boolean matches(CharSequence rawPassword, String encodePassword) {
        // 判断密码是否存在
        if (rawPassword == null) {
            return false;
        }

        //通过md5加密后的密码
        LOG.error("=======================rawPassword: " + rawPassword + "=================================");
        LOG.error("=======================encodePassword: " + encodePassword + "=================================");
        String pass = this.encode(rawPassword.toString());
        LOG.error("=======================pass: " + pass + "=================================");
        //比较密码是否相等的问题
        // return pass.equals(encodePassword);
        return MD5Utils.getSaltverifyMD5(rawPassword.toString(), encodePassword);
    }
}
