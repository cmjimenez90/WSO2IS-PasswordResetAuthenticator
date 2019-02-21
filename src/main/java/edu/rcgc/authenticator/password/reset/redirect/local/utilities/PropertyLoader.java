package edu.rcgc.authenticator.password.reset.redirect.local.utilities;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.utils.CarbonUtils;

import edu.rcgc.authenticator.password.reset.redirect.local.PasswordResetRedirectAuthenticatorConstants;

public class PropertyLoader {

	private static final Log log = LogFactory.getLog(PropertyLoader.class);
	private static Properties properties = new Properties();
	
	public static final String WSO2_IDENTITY_PROPERTIES_FILE_NAME = "identity-mgt.properties";
	public static String PROPERTY_PASSWORD_RESET_REDIRECT_URL = "EDU.RCGC.PASSWORD.RESET.REDIRECT.AUTHENTICATOR.REDIRECT.URL";
	public static String PROPERTY_PASSWORD_RESET_CLAIM_URL = "EDU.RCGC.PASSWORD.RESET.REDIRECT.AUTHENTICATOR.CLAIM.URL";
	public static String PROPERTY_PASSWORD_RESET_FLAG = "EDU.RCGC.PASSWORD.RESET.REDIRECT.AUTHENTICATOR.RESET.FLAG";

	private PropertyLoader() {}
	
	static {
		loadProperties();
	}
	
	public static void loadProperties() {
		FileInputStream fileInputStream = null;
        String configPath = (CarbonUtils.getCarbonConfigDirPath() + File.separator + "identity" + File.separator);

        try {
            configPath = configPath + WSO2_IDENTITY_PROPERTIES_FILE_NAME;
            fileInputStream = new FileInputStream(new File(configPath));
            properties.load(fileInputStream);
        } catch (FileNotFoundException e) {
            throw new RuntimeException("identity-mgt.properties file not found in " + configPath, e);
        } catch (IOException e) {
            throw new RuntimeException("identity-mgt.properties file reading error from " + configPath, e);
        } finally {
            if (fileInputStream != null) {
                try {
                    fileInputStream.close();
                } catch (Exception e) {
                    log.error("Error occured while closing stream :" + e);
                }
            }
        }
    }
	
	public static String getLoginPageUrl() {
		String loginUrl = properties.getProperty(PROPERTY_PASSWORD_RESET_REDIRECT_URL);
		if(!(loginUrl == null))
			return loginUrl;
		return PasswordResetRedirectAuthenticatorConstants.DEFAULT_PASSWORD_RESET_REDIRECT_URL;
	}
	
	public static String getResetClaimUrl() {
		String claimUrl = properties.getProperty(PROPERTY_PASSWORD_RESET_CLAIM_URL);
		if(!(claimUrl == null))
			return claimUrl;
		return PasswordResetRedirectAuthenticatorConstants.DEFAULT_PASSWORD_RESET_CLAIM_URL;
	}
	
	
}



