package edu.rcgc.authenticator.password.reset.redirect.local;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import edu.rcgc.authenticator.password.reset.redirect.local.utilities.PropertyLoader;

public class PasswordResetRedirectAuthenticator extends AbstractApplicationAuthenticator
		implements LocalApplicationAuthenticator {
	 	private static final long serialVersionUID = 4345354156955223654L;
	    private static final Log log = LogFactory.getLog(PasswordResetRedirectAuthenticator.class);
	       
	    @Override
		public boolean canHandle(HttpServletRequest httpServletRequest) {
			return true;
		}

		@Override
		public String getContextIdentifier(HttpServletRequest httpServletRequest) {
			return httpServletRequest.getParameter("sessionDataKey");
		}

		@Override
		public String getFriendlyName() {
			return PasswordResetRedirectAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
		}

		@Override
		public String getName() {
			return PasswordResetRedirectAuthenticatorConstants.AUTHENTICATOR_NAME;
		}

		@Override
		protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
				AuthenticationContext context) throws AuthenticationFailedException {		
		}
		
		@Override
		public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response, AuthenticationContext context)
        		throws AuthenticationFailedException, LogoutFailedException {
        		if(context.isLogoutRequest()) {
        			if(log.isDebugEnabled()) {
        				log.debug("context was a logout request");
        			}
        			return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        		}
        		else {
        			return initiateAuthRequest(request, response, context);
        		}
        }
		
		protected AuthenticatorFlowStatus initiateAuthRequest(HttpServletRequest request,HttpServletResponse response, AuthenticationContext context) throws AuthenticationFailedException {
				if(log.isDebugEnabled()) {
					log.debug(String.format("Class: %s Method: initiateAuthRequest called",PasswordResetRedirectAuthenticator.class.getName()));
				}	
				AuthenticatedUser authenticatedUser = getUsername(context);

				if (authenticatedUser == null) {
					throw new AuthenticationFailedException("No authenticated user found. Can not proceed");
				}

				String username = null;
				String tenantDomain = null;
				String userstoreDomain = null;
				String tenantAwareUsername = null;
				
				username = authenticatedUser.getAuthenticatedSubjectIdentifier();
				tenantDomain = authenticatedUser.getTenantDomain();
				userstoreDomain = authenticatedUser.getUserStoreDomain();
				tenantAwareUsername = UserCoreUtil.addDomainToName(username, userstoreDomain);

				UserStoreManager userStoreManager = getUserStoreManager(IdentityTenantUtil.getTenantId(tenantDomain));
				
				if(userResetClaimExist(userStoreManager, tenantAwareUsername)) {
					redirectUserForPasswordReset(response, context);
					context.setCurrentAuthenticator(getName());
					if(log.isDebugEnabled()) {
						log.debug("Returning INCOMPLETE Flow Status: User was redirected for Reset");
					}
	                return AuthenticatorFlowStatus.INCOMPLETE;
				}			
				 updateAuthenticatedUserInStepConfig(context, authenticatedUser);
				 if(log.isDebugEnabled()) {
						log.debug("Returning Success Complete Flow Status: User does not need reset");
				 }
			     return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
		}
		
		private AuthenticatedUser getUsername(AuthenticationContext context) {
			AuthenticatedUser authenticatedUser = null;
			for (int i = 1; i <= context.getSequenceConfig().getStepMap().size(); i++) {
				StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(i);
				if (stepConfig.getAuthenticatedUser() != null && stepConfig.getAuthenticatedAutenticator()
						.getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {
					authenticatedUser = stepConfig.getAuthenticatedUser();
					break;
				}
			}
			return authenticatedUser;
		}
		
		private UserStoreManager getUserStoreManager(int tenantId) throws AuthenticationFailedException{
			try {
				RealmService realmService = IdentityTenantUtil.getRealmService();
				UserRealm userRealm = realmService.getTenantUserRealm(tenantId);
				return (UserStoreManager) userRealm.getUserStoreManager();
			} catch (UserStoreException e) {
				throw new AuthenticationFailedException("Error occured while loading userrealm/userstoremanager", e);
			}
		}
		
		private boolean userResetClaimExist(UserStoreManager userStoreManager, String tenantAwareUsername) throws AuthenticationFailedException {
			try {
				String userResetClaimURL = PropertyLoader.getResetClaimUrl();
				String userResetClaimValue =  userStoreManager.getUserClaimValue(tenantAwareUsername, userResetClaimURL, null);
				if(userResetClaimValue != null) {
					if(log.isDebugEnabled()) {
						log.debug(String.format("User: %s has a valid claim", tenantAwareUsername));
					}
					return true;
				}
					return false;
			} catch (UserStoreException e) {
				throw new AuthenticationFailedException(
						"Error occured while loading user claim - http://wso2.org/claims/lastPasswordChangedTimestamp", e);
			}
		}
		
		/*
		 * Called when the initiateAuthRequest can skip the rest of the process. forces the context to step through to the end of the auth process.
		*/
		private void updateAuthenticatedUserInStepConfig(AuthenticationContext context,AuthenticatedUser authenticatedUser) {
			for (int i = 1; i <= context.getSequenceConfig().getStepMap().size(); i++) {
				StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(i);
				stepConfig.setAuthenticatedUser(authenticatedUser);
			}
			if(log.isDebugEnabled()) {
				log.debug(String.format("Seting Context subject as %s, step update complete",authenticatedUser));
			}
			context.setSubject(authenticatedUser);
		}

		private void redirectUserForPasswordReset(HttpServletResponse response, AuthenticationContext context) throws AuthenticationFailedException {
			String loginPage = PropertyLoader.getLoginPageUrl();
			String queryParams = FrameworkUtils
	                .getQueryStringWithFrameworkContextId(context.getQueryParams(),
	                        context.getCallerSessionKey(),
	                        context.getContextIdentifier());
			try {
	            String retryParam = "";
	            
	            if (context.isRetrying()) {
	                retryParam = "&authFailure=true&authFailureMsg=login.fail.message";
	            }
	            String encodedRedirectUrl = (response.encodeRedirectURL(loginPage + ("?" + queryParams))
	            		+ "&authenticators=" + getName() + ":" + "LOCAL" + retryParam);
	            if(log.isDebugEnabled()) {
					log.debug(String.format("Redirection being sent to: %s", encodedRedirectUrl));
				}
	            response.sendRedirect(encodedRedirectUrl);  
	       } 
		   catch (IOException e) {
	           throw new AuthenticationFailedException(e.getMessage(), e);
	       }
		}
		
}
