package org.oscarehr.util;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import javax.ws.rs.core.Response;
import javax.servlet.http.HttpSession;
import org.apache.cxf.jaxrs.client.WebClient;
import org.apache.cxf.interceptor.LoggingInInterceptor;
import org.apache.cxf.interceptor.LoggingOutInterceptor;
import java.io.PrintWriter;
import org.apache.cxf.jaxrs.ext.form.Form;
//import javax.servlet.http.HttpSession;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;

import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.util.Enumeration;
import java.util.List;
import java.net.URI;
import java.util.UUID;
import java.net.URLEncoder;

import java.nio.charset.StandardCharsets;


import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.openid.connect.sdk.*;

import org.oscarehr.PMmodule.service.ProviderManager;

import org.oscarehr.common.dao.SecurityDao;
//import org.oscarehr.common.dao.ProviderDao;
import org.oscarehr.PMmodule.dao.ProviderDao;
import org.oscarehr.common.dao.SystemPreferencesDao;
import org.oscarehr.common.dao.FacilityDao;

import org.oscarehr.common.dao.ProviderPreferenceDao;
import org.oscarehr.common.model.SystemPreferences;

import org.oscarehr.common.model.ProviderPreference;
import org.oscarehr.common.model.Security;
import org.oscarehr.common.model.Provider;
import org.oscarehr.common.model.Facility;
import oscar.log.*;
import net.sf.json.JSONObject;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.JWT;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import com.nimbusds.oauth2.sdk.token.Tokens;

public class OIDCFilter implements Filter {


    /// tokenUrl = keycloakUrl+"/realms/"+realmName+"/protocol/openid-connect/token";  //just an example of what it looks like with keycloak
    /*
String keycloakUrl = "http://host.docker.internal:8180";
    String realmName = "OSCARTEST"; 
http://host.docker.internal:8180/realms/OSCARTEST/protocol/openid-connect/auth?client_id=oscarweb&scope=openid&response_type=code&redirect_uri=http://localhost:8080/oscar/proc.jsp");


POST {keycloak-url}/realms/{realm-name}/protocol/openid-connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code={code}
&redirect_uri={redirect-uri}
&client_id={client-id}
&client_secret={client-secret}

//keycloakUrl+"/realms/"+realmName+"/protocol/openid-connect/logout?id_token_hint="+idToken+"&post_logout_redirect_uri=http://localhost:8080/oscar/");
*/



	private static final Logger logger = MiscUtils.getLogger();
    
    String issuerString = "http://host.docker.internal:8180/realms/OSCARTEST";
    
    String REDIRECT_URI = "http://localhost:8881/oscar/proc.jsp";
    String CLIENT_ID = "oscarweb2";

    // Construct the redirect URI for post-logout
    URI postLogoutRedirectURI = null;// new URI("http://localhost:8881/oscar/");

    SystemPreferencesDao systemPreferencesDao = SpringUtils.getBean(SystemPreferencesDao.class);
    private ProviderPreferenceDao providerPreferenceDao = (ProviderPreferenceDao) SpringUtils.getBean("providerPreferenceDao");
    private ProviderManager providerManager = (ProviderManager) SpringUtils.getBean("providerManager");

    SystemPreferences forceLogoutInactivePref = systemPreferencesDao.findPreferenceByName("force_logout_when_inactive");
    SystemPreferences forceLogoutInactiveTimePref = systemPreferencesDao.findPreferenceByName("force_logout_when_inactive_time");

    SecurityDao securityDao = (SecurityDao) SpringUtils.getBean("securityDao");
    FacilityDao facilityDao = (FacilityDao) SpringUtils.getBean("facilityDao");
    ProviderDao providerDao = (ProviderDao) SpringUtils.getBean("providerDao");
    OIDCProviderMetadata opMetadata = null;        

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // Initialization code
        try{
            Issuer issuer = new Issuer(issuerString);//"http://host.docker.internal:8180/realms/OSCARTEST");
	    postLogoutRedirectURI = new URI("http://localhost:8881/oscar/");
            // Resolve the OpenID provider metadata
            opMetadata = OIDCProviderMetadata.resolve(issuer);

            // Print the metadata
            System.out.println(opMetadata.toJSONObject());
        }catch(Exception e){
            logger.error("ERROR getting OIDC metadata",e);
        }
        //


    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

       HttpServletRequest httpRequest = (HttpServletRequest) request;
       HttpServletResponse httpResponse = (HttpServletResponse) response;

       String ip = request.getRemoteAddr();

	   String contextPath = httpRequest.getContextPath();
	   String requestURI = httpRequest.getRequestURI();

       HttpSession session = httpRequest.getSession(false);

       if(requestURI.startsWith(contextPath + "/logout.jsp")){ // User is looking to logout.

          if(session != null ){
                String idToken = (String) session.getAttribute("idToken");
                String user = (String) session.getAttribute("user");
                session.invalidate();
                String logMessage = "";
                if ("true".equalsIgnoreCase(request.getParameter("autoLogout"))) {logMessage = "autoLogout";}
                LogAction.addLog((String)user, LogConst.LOGOUT, LogConst.CON_LOGIN, logMessage, ip);

    
                try{

                    // Construct the end-session endpoint URI
                    URI endSessionEndpoint = opMetadata.getEndSessionEndpointURI();

                    // Construct the logout URI with the redirect parameter and id_token_hint-- which stops keycloak from asking the user again if they really want to logout.
                    String logoutURI = endSessionEndpoint + "?id_token_hint="+idToken+"&post_logout_redirect_uri=" + URLEncoder.encode(postLogoutRedirectURI.toString(), StandardCharsets.UTF_8.toString());

                    httpResponse.sendRedirect(logoutURI);
    
                }catch(Exception e){
                    logger.error("Error with Logout",e);
                }

                return;
          }
    
       }

	   System.out.println("#############3contextPath "+contextPath+" requestURI "+requestURI+ " session "+(session != null)+" usersession "+(session != null && session.getAttribute("user") != null));
       
       if (session != null && session.getAttribute("user") != null) { //already logged in. Nothing to do with this request
          chain.doFilter(request, response);        
          return;
       }

	   if (requestURI.startsWith(contextPath + "/proc.jsp")){ 

	       String sessionState = httpRequest.getParameter("session_state");
           String code = httpRequest.getParameter("code");

           try {
           
              AuthorizationCode authorizationCode = new AuthorizationCode(code);
              URI redirectURI = URI.create(REDIRECT_URI);

              CodeVerifier codeVerifier =  (CodeVerifier) session.getAttribute("codeVerifier");
              session.removeAttribute("codeVerifier");

              TokenRequest tokenRequest = new TokenRequest(
                    opMetadata.getTokenEndpointURI(),
                    new ClientID(CLIENT_ID),
                    new AuthorizationCodeGrant(authorizationCode, redirectURI,codeVerifier));


              System.out.println("build token str:"+tokenRequest.toHTTPRequest().getQuery());

              TokenResponse tokenResponse = TokenResponse.parse(tokenRequest.toHTTPRequest().send());

              System.out.println("toJSONObject()"+tokenResponse.toHTTPResponse().getContent());

              if (!tokenResponse.indicatesSuccess()) {
                // Handle error
                 httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token exchange failed");
                 return;
              }

              try {
                 tokenResponse = OIDCTokenResponseParser.parse(tokenResponse.toHTTPResponse());
              } catch (ParseException e) {
                 logger.error("OIDC token parse error",e);
                 httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token exchange failed");
                 return;
                 // TODO proper error handling
              }

              OIDCTokenResponse oidcTokenResponse = (OIDCTokenResponse) tokenResponse;
              OIDCTokens tokens = oidcTokenResponse.getOIDCTokens();
            
              String accessToken = tokens.getAccessToken().getValue();
              String idToken = tokens.getIDTokenString();
    
              if (accessToken != null) {
                
                    DecodedJWT decodedJWT = JWT.decode(accessToken);


                    List<Security> securityResults = securityDao.findByOneIdKey(decodedJWT.getSubject()); 
                    Security securityRecord = null;

                    if(securityResults.size() > 0){
                        securityRecord = securityResults.get(0);
                        //NEED TO VALIDATE TOKENS
                        //Start of session management
                        //HttpSession session = httpRequest.getSession(false);
                        if (session != null) {
                            session.invalidate();
                        }
                        session = httpRequest.getSession(); // Create a new session for this user
                       
                        setOscarSessionRequirements(session, securityRecord, decodedJWT, accessToken, idToken);

                        Cookie cookie = new Cookie("access_token", accessToken);
                        //cookie.setHttpOnly(true);
                        //cookie.setSecure(true); // Ensure this is true in production
                        cookie.setPath("/");
                        cookie.setMaxAge(3600); // Set the expiration time as needed
                        httpResponse.addCookie(cookie);

                        LoggedInInfo loggedInInfo = LoggedInUserFilter.generateLoggedInInfoFromSession(httpRequest);

                        System.out.println("redirect provider control");
                        
                        httpResponse.sendRedirect("/oscar/provider/providercontrol.jsp");
                        return;    
                    }
            
                }
            }catch(Exception e){
                logger.error("try ",e);
            }
            
	    chain.doFilter(request, response);		
	    return;

        }
        
        String authHeader = httpRequest.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            System.out.println("DOES THIS GET CALLED ??????");
            String token = authHeader.substring(7);
            // Validate the token
            if (validateToken(token)) {
                chain.doFilter(request, response);
                return;
            }
        }

        // Redirect to OAuth2 provider if token is invalid or missing
        
        //httpResponse.sendRedirect("http://host.docker.internal:8180/realms/OSCARTEST/broker/keycloak-oidc/endpoint");
        
        System.out.println("redirecting to auth");

        // Step 1: Redirect to the authorization endpoint
            State state = new State(UUID.randomUUID().toString());
            CodeVerifier codeVerifier = new CodeVerifier();
            CodeChallenge codeChallenge = CodeChallenge.compute(CodeChallengeMethod.S256, codeVerifier);

            session = httpRequest.getSession();
            session.setAttribute("codeVerifier",codeVerifier);

            AuthenticationRequest authRequest = new AuthenticationRequest.Builder(
                    new ResponseType("code"),
                    new Scope("openid"),
                    new ClientID(CLIENT_ID),
                    URI.create(REDIRECT_URI))
                    .endpointURI(opMetadata.getAuthorizationEndpointURI())
                    .state(state)
                    .codeChallenge(codeChallenge, CodeChallengeMethod.S256)
                    .build();

            System.out.println("build auth str:"+authRequest.toURI().toString());
            httpResponse.sendRedirect(authRequest.toURI().toString());

    }

    private boolean validateToken(String token) {
        
        System.out.println("in Validate Token "+token);
        // Token validation logic
        return true; // Replace with actual validation
    }

    private void setOscarSessionRequirements(HttpSession session,Security securityRecord,DecodedJWT decodedJWT,String accessToken,String idToken){
         // set session max interval from system preference
                        session.setMaxInactiveInterval((forceLogoutInactivePref != null && forceLogoutInactivePref.getValueAsBoolean() && forceLogoutInactiveTimePref != null ? Integer.parseInt(forceLogoutInactiveTimePref.getValue()) : 120) * 60);
                    
                              /*
                            String[] strAuth = new String[6];
                            strAuth[0] = security.getProviderNo();
                            strAuth[1] = firstname;
                            strAuth[2] = lastname;
                            strAuth[3] = profession;
                            strAuth[4] = rolename;
                            strAuth[5] = expired_days;
                        */    


                        String providerNo = securityRecord.getProviderNo();
                        session.setAttribute("user", providerNo);

                        session.setAttribute("accessToken",accessToken);
                        session.setAttribute("idToken",idToken);

                        

                        session.setAttribute("userfirstname", decodedJWT.getClaim("family_name").asString());
                        session.setAttribute("userlastname", decodedJWT.getClaim("given_name").asString());
                        session.setAttribute("userrole", "doctor"); //???? can this come from the resource roles????
                        session.setAttribute("oscar_context_path", decodedJWT.getClaim("allowed-origins").asString());
                        session.setAttribute("expired_days", "100"); // ????????????? do this need to be handled in oscar then?
                     
                        String default_pmm = null;
            
                        // get preferences from preference table
                        ProviderPreference providerPreference=providerPreferenceDao.find(providerNo);
                
                        if (providerPreference==null) providerPreference=new ProviderPreference();
                        
                        session.setAttribute(SessionConstants.LOGGED_IN_PROVIDER_PREFERENCE, providerPreference);
                        
                        session.setAttribute("starthour", providerPreference.getStartHour().toString());
                        session.setAttribute("endhour", providerPreference.getEndHour().toString());
                        session.setAttribute("everymin", providerPreference.getEveryMin().toString());
                        session.setAttribute("groupno", providerPreference.getMyGroupNo());

                       
                        Provider provider = providerManager.getProvider(providerNo);
                        session.setAttribute(SessionConstants.LOGGED_IN_PROVIDER, provider);
                        session.setAttribute(SessionConstants.LOGGED_IN_SECURITY, securityRecord);
                        List<Integer> facilityIds = providerDao.getFacilityIds(providerNo);
                        Facility facility=facilityDao.find(facilityIds.get(0));
                        session.setAttribute("currentFacility", facility);
                     

    }

    @Override
    public void destroy() {
        // Cleanup code
    }
}

