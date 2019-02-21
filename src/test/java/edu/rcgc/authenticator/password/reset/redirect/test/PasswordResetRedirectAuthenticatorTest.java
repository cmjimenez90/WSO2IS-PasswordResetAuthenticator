package edu.rcgc.authenticator.password.reset.redirect.test;

import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.reflect.Whitebox;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.utils.CarbonUtils;

import edu.rcgc.authenticator.password.reset.redirect.local.PasswordResetRedirectAuthenticator;
import edu.rcgc.authenticator.password.reset.redirect.local.PasswordResetRedirectAuthenticatorConstants;

@PrepareForTest({IdentityTenantUtil.class, IdentityUtil.class, ConfigurationFacade.class, FrameworkUtils.class, CarbonUtils.class})
public class PasswordResetRedirectAuthenticatorTest {
	
    @Mock
    private HttpServletRequest httpServletRequest;

    @Mock
    private HttpServletResponse httpServletResponse;

    @Spy
    private AuthenticationContext context;

    @Mock
    private SequenceConfig sequenceConfig;

    @Mock
    private Map<Integer, StepConfig> mockedMap;

    @Mock
    private StepConfig stepConfig;
    
    @Mock
    private AuthenticatorConfig authenticatorConfig;
    
    private PasswordResetRedirectAuthenticator passwordResetRedirectAuthenticator;
    
	private static final String TEST_CONTEXT_IDENTIFIER = "arbitrarySessionId";
	private static final String TEST_USER_IDENTIFIER = "testUserIdentifier";

    @BeforeMethod
    public void setUp() throws Exception {
    	passwordResetRedirectAuthenticator = new PasswordResetRedirectAuthenticator();
        initMocks(this);
        when(context.getSequenceConfig()).thenReturn(sequenceConfig);
        when(sequenceConfig.getStepMap()).thenReturn(mockedMap);
        when(mockedMap.get(anyObject())).thenReturn(stepConfig);
    }

    @AfterMethod
    public void tearDown() throws Exception {
    }

    @Test
    public void testCanHandleTrue() {
        Assert.assertEquals(passwordResetRedirectAuthenticator.canHandle(httpServletRequest), true);
    }
    @Test
    public void testGetFriendlyName() {
        Assert.assertEquals(passwordResetRedirectAuthenticator.getFriendlyName(),
                PasswordResetRedirectAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME);
    }

    @Test
    public void testGetName() {
        Assert.assertEquals(passwordResetRedirectAuthenticator.getName(),
                PasswordResetRedirectAuthenticatorConstants.AUTHENTICATOR_NAME);
    }

    @Test
    public void testGetContextIdentifier() {
        when(httpServletRequest.getParameter("sessionDataKey")).thenReturn(TEST_CONTEXT_IDENTIFIER);
        Assert.assertEquals(passwordResetRedirectAuthenticator.getContextIdentifier(httpServletRequest), TEST_CONTEXT_IDENTIFIER);
    }
    @Test
    public void testGetUsername() throws Exception {
       Whitebox.invokeMethod(passwordResetRedirectAuthenticator, "getUsername", context);
    }
    
    @Test
    public void testProcessReturnsSuccessCompletedWhenIsLogOutRequest() throws AuthenticationFailedException, LogoutFailedException{
    	when(context.isLogoutRequest()).thenReturn(true);
    	Assert.assertEquals(passwordResetRedirectAuthenticator.process(httpServletRequest, httpServletResponse, context), AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }
    @Test
    public void testProcessShouldCallInitiateAuthRequestIfNotLogOutRequest() throws Exception {
    	when(context.isLogoutRequest()).thenReturn(false);
    	PasswordResetRedirectAuthenticator passwordResetRedirectAuthenticatorSpy =  PowerMockito.spy(new PasswordResetRedirectAuthenticator());
    	PowerMockito.doReturn(AuthenticatorFlowStatus.SUCCESS_COMPLETED).when(passwordResetRedirectAuthenticatorSpy, "initiateAuthRequest",httpServletRequest,httpServletResponse,context);
    	passwordResetRedirectAuthenticatorSpy.process(httpServletRequest, httpServletResponse, context);
    	PowerMockito.verifyPrivate(passwordResetRedirectAuthenticatorSpy).invoke("initiateAuthRequest",httpServletRequest,httpServletResponse,context);
    }
    @Test
    public void testUpdateAuthenticatedUserInStepConfig() throws Exception {
    	AuthenticatedUser mockUser = Mockito.mock(AuthenticatedUser.class);
    	when(context.getSequenceConfig().getStepMap().get(anyInt())).thenReturn(stepConfig);   
    	when(mockUser.getAuthenticatedSubjectIdentifier()).thenReturn(TEST_USER_IDENTIFIER);
    	Whitebox.invokeMethod(passwordResetRedirectAuthenticator, "updateAuthenticatedUserInStepConfig", context, mockUser);
    	Assert.assertEquals(context.getSubject().getAuthenticatedSubjectIdentifier(), mockUser.getAuthenticatedSubjectIdentifier());
    }
    
 
           
}
