/**
 * Copyright (c) 2001-2002. Department of Family Medicine, McMaster University. All Rights Reserved.
 * This software is published under the GPL GNU General Public License.
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version. 
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * This software was written for the
 * Department of Family Medicine
 * McMaster University
 * Hamilton
 * Ontario, Canada
 */
package com.quatro.web.admin;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

import javax.servlet.ServletRequest;
import javax.servlet.jsp.PageContext;

import org.oscarehr.common.dao.SecurityDao;
import org.oscarehr.common.model.Security;
import org.oscarehr.util.MiscUtils;
import org.oscarehr.util.SpringUtils;

import oscar.MyDateFormat;
import oscar.log.LogAction;
import oscar.log.LogConst;

import com.j256.twofactorauth.TimeBasedOneTimePasswordUtil;

/**
 * Helper class for securityaddsecurity.jsp page.
 */
public class SecurityAddSecurityHelper {

	private SecurityDao securityDao = SpringUtils.getBean(SecurityDao.class);

	/**
	 * Adds a security record (i.e. user login information) for the provider.
	 * <p/>
	 * Processing status is available as a "message" variable.
	 * 
	 * @param pageContext
	 * 		JSP page context
	 */
	public void addProvider(PageContext pageContext) {
		String message = process(pageContext);
		pageContext.setAttribute("message", message);
	}
	
	public static String digestPassword(String rawPassword) throws NoSuchAlgorithmException {
		StringBuilder sbTemp = new StringBuilder();
		MessageDigest md = MessageDigest.getInstance("SHA");
		byte[] btNewPasswd = md.digest(rawPassword.getBytes());
		for (int i = 0; i < btNewPasswd.length; i++)
			sbTemp = sbTemp.append(btNewPasswd[i]);
		return sbTemp.toString();
	}
	
	private String process(PageContext pageContext) {
		ServletRequest request = pageContext.getRequest();
		
		String digestedPassword = null;
		
        try {
        	 	digestedPassword =  digestPassword(request.getParameter("password"));
        } catch (NoSuchAlgorithmException e) {
        		MiscUtils.getLogger().error("Unable to get SHA message digest", e);
        		return "admin.securityaddsecurity.msgAdditionFailure";
        }

		boolean isUserRecordAlreadyCreatedForProvider = !securityDao.findByProviderNo(request.getParameter("provider_no")).isEmpty();
		if (isUserRecordAlreadyCreatedForProvider) return "admin.securityaddsecurity.msgLoginAlreadyExistsForProvider";

		boolean isUserAlreadyExists = securityDao.findByUserName(request.getParameter("user_name")).size() > 0;
		if (isUserAlreadyExists) return "admin.securityaddsecurity.msgAdditionFailureDuplicate";

		Security s = new Security();
		s.setUserName(request.getParameter("user_name"));
		s.setPassword(digestedPassword);
		s.setProviderNo(request.getParameter("provider_no"));
		s.setPin(request.getParameter("pin"));
		s.setBExpireset(request.getParameter("b_ExpireSet") == null ? 0 : Integer.parseInt(request.getParameter("b_ExpireSet")));
		s.setDateExpiredate(MyDateFormat.getSysDate(request.getParameter("date_ExpireDate")));
		s.setBLocallockset(request.getParameter("b_LocalLockSet") == null ? 0 : Integer.parseInt(request.getParameter("b_LocalLockSet")));
		s.setBRemotelockset(request.getParameter("b_RemoteLockSet") == null ? 0 : Integer.parseInt(request.getParameter("b_RemoteLockSet")));
	    String secret =  TimeBasedOneTimePasswordUtil.generateBase32Secret();
	    s.setTotpSecret(secret);
    	if (request.getParameter("forcePasswordReset") != null && request.getParameter("forcePasswordReset").equals("1")) {
    	    s.setForcePasswordReset(Boolean.TRUE);
    	} else {
    		s.setForcePasswordReset(Boolean.FALSE);  
        }
    	
    	if (request.getParameter("2fa") != null && request.getParameter("2fa").equals("1")) {
    	    s.setTotpEnabled(Boolean.TRUE);
    	} else {
    		s.setTotpEnabled(Boolean.FALSE);  
        }
		
    	s.setPasswordUpdateDate(new Date());
    	s.setPinUpdateDate(new Date());
    	
		securityDao.persist(s);

		LogAction.addLog((String) pageContext.getSession().getAttribute("user"), LogConst.ADD, LogConst.CON_SECURITY, request.getParameter("user_name"), request.getRemoteAddr());

		// hurrah - it worked
		return "admin.securityaddsecurity.msgAdditionSuccess";
	}
}