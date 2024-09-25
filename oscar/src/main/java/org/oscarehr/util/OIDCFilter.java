package org.oscarehr.util;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
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
import net.sf.json.JSONObject;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.JWT;


public class OAuth2Filter implements Filter {

	private static final Logger logger = MiscUtils.getLogger();
    String keycloakUrl = "http://host.docker.internal:8180";
    String realmName = "OSCARTEST"; 

    SystemPreferencesDao systemPreferencesDao = SpringUtils.getBean(SystemPreferencesDao.class);
    private ProviderPreferenceDao providerPreferenceDao = (ProviderPreferenceDao) SpringUtils.getBean("providerPreferenceDao");
    private ProviderManager providerManager = (ProviderManager) SpringUtils.getBean("providerManager");

    
    
    SystemPreferences forceLogoutInactivePref = systemPreferencesDao.findPreferenceByName("force_logout_when_inactive");
    SystemPreferences forceLogoutInactiveTimePref = systemPreferencesDao.findPreferenceByName("force_logout_when_inactive_time");

    SecurityDao securityDao = (SecurityDao) SpringUtils.getBean("securityDao");
    FacilityDao facilityDao = (FacilityDao) SpringUtils.getBean("facilityDao");
    ProviderDao providerDao = (ProviderDao) SpringUtils.getBean("providerDao");
            

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // Initialization code
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

//

	   String contextPath = httpRequest.getContextPath();
	   String requestURI = httpRequest.getRequestURI();


       HttpSession session = httpRequest.getSession(false);


       if(requestURI.startsWith(contextPath + "/logout.jsp")){

          if(session != null ){
                String idToken = (String) session.getAttribute("idToken");
                session.invalidate();
                //request.getSession();
                //String ip = request.getRemoteAddr();
                //String logMessage = "";
                //if ("true".equalsIgnoreCase(request.getParameter("autoLogout"))) {
                //    logMessage = "autoLogout";
                //}
                //LogAction.addLog((String)user, LogConst.LOGOUT, LogConst.CON_LOGIN, logMessage, ip);
                httpResponse.sendRedirect(keycloakUrl+"/realms/"+realmName+"/protocol/openid-connect/logout?id_token_hint="+idToken+"&post_logout_redirect_uri=http://localhost:8080/oscar/");
                //;
                 //redirect the browser to  http://auth-server/auth/realms/{realm-name}/protocol/openid-connect/logout?redirect_uri=encodedRedirectUri
                return;
          }
            
      
        }
  
  
  
  
       

	   System.out.println("#############3contextPath "+contextPath+" requestURI "+requestURI+ " session "+(session != null)+" usersession "+(session != null && session.getAttribute("user") != null));


       
       if (session != null && session.getAttribute("user") != null) {
          chain.doFilter(request, response);        
          return;
       }

	   if (requestURI.startsWith(contextPath + "/proc.jsp")){

	       String sessionState = httpRequest.getParameter("session_state");
           String code = httpRequest.getParameter("code");

           String tokenUrl = keycloakUrl+"/realms/"+realmName+"/protocol/openid-connect/token";

           Enumeration<String> parameterNames = httpRequest.getParameterNames();
    
           while (parameterNames.hasMoreElements()) {
               String paramName = parameterNames.nextElement();
               String paramValue = request.getParameter(paramName);
               System.out.println("############### "+paramName + ": " + paramValue);
           }

            
            Response response2 = null;
            try {
                WebClient wc = WebClient.create(tokenUrl); 
                
                WebClient.getConfig(wc).getInInterceptors().add(new LoggingInInterceptor());
                WebClient.getConfig(wc).getOutInterceptors().add(new LoggingOutInterceptor(new PrintWriter(System.out, true)));


                MultivaluedMap <String,String> formData = new MultivaluedHashMap<>();
                formData.add("grant_type", "authorization_code");
                formData.add("client_id", "oscarweb");
                formData.add("code", code);
                formData.add("redirect_uri","http://localhost:8080/oscar/proc.jsp");
               

        
                response2 = wc.header("Content-Type", "application/x-www-form-urlencoded").post(formData);

                String body = response2.readEntity(String.class);

                System.out.println("body === "+body);

                JSONObject tokens = JSONObject.fromObject(body);
            
            
                String accessToken = tokens.getString("access_token");
                String idToken = tokens.getString("id_token");
    
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
                        //loggedInInfo.setCurrentFacility((Facility) session.getAttribute(SessionConstants.CURRENT_FACILITY));

                        /*
String facilityIdString=request.getParameter(SELECTED_FACILITY_ID);
                Facility facility=facilityDao.find(Integer.parseInt(facilityIdString));
                request.getSession().setAttribute(SessionConstants.CURRENT_FACILITY, facility);
                        */

                        LoggedInInfo loggedInInfo = LoggedInUserFilter.generateLoggedInInfoFromSession(httpRequest);

                        System.out.println("redirect provider control");
                        
                        httpResponse.sendRedirect("/oscar/provider/providercontrol.jsp");
                        return;    
                    }
            
                }
            }catch(Exception e){
                logger.error("try ",e);
            }
            
            
/*

http://host.docker.internal:8180/realms/OSCARTEST/protocol/openid-connect/auth?client_id=oscarweb&scope=openid&response_type=code&redirect_uri=http://localhost:8080/oscar/proc.jsp");


POST {keycloak-url}/realms/{realm-name}/protocol/openid-connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code={code}
&redirect_uri={redirect-uri}
&client_id={client-id}
&client_secret={client-secret}
*/
           

	    chain.doFilter(request, response);		
	    return;

        }
        
        String authHeader = httpRequest.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
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
        httpResponse.sendRedirect("http://host.docker.internal:8180/realms/OSCARTEST/protocol/openid-connect/auth?client_id=oscarweb&scope=openid&response_type=code&redirect_uri=http://localhost:8080/oscar/proc.jsp");
    }

    private boolean validateToken(String token) {
        
        System.out.println("in Validate Token "+token);
        // Token validation logic
        return true; // Replace with actual validation
    }

    @Override
    public void destroy() {
        // Cleanup code
    }
}

