package org.oscarehr.integration.dhdr;
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
public class AuditInfo {
	public static final String DHDR = "DHDR";
	public static final String DHIR = "DHIR";

	public static final String SEARCH = "SEARCH";
	public static final String RETRIEVAL = "RETRIEVAL";
	public static final String SUBMISSION = "SUBMISSION";
	
	private Integer demographicNo = null;
	private String externalSystem = null;
	private String transactionType = null;
	
	public AuditInfo(String externalSystem, String transactionType, Integer demographicNo) {
		this.demographicNo = demographicNo;
		this.externalSystem = externalSystem;
		this.transactionType = transactionType;
	}
	public Integer getDemographicNo() {
		return demographicNo;
	}
	public void setDemographicNo(Integer demographicNo) {
		this.demographicNo = demographicNo;
	}
	public String getExternalSystem() {
		return externalSystem;
	}
	public void setExternalSystem(String externalSystem) {
		this.externalSystem = externalSystem;
	}
	public String getTransactionType() {
		return transactionType;
	}
	public void setTransactionType(String transactionType) {
		this.transactionType = transactionType;
	}
}
