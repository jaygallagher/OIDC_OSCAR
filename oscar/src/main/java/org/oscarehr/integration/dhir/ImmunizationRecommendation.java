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
package org.oscarehr.integration.dhir;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class ImmunizationRecommendation {
	private List<Coding> codes = new ArrayList<Coding>(); 
	private String targetDisease;
	private Coding forecastStatus;
	private Date date;
	
	public List<Coding> getCodes() {
		return codes;
	}
	public void setCodes(List<Coding> codes) {
		this.codes = codes;
	}
	public String getTargetDisease() {
		return targetDisease;
	}
	public void setTargetDisease(String targetDisease) {
		this.targetDisease = targetDisease;
	}
	public Coding getForecastStatus() {
		return forecastStatus;
	}
	public void setForecastStatus(Coding forecastStatus) {
		this.forecastStatus = forecastStatus;
	}
	public Date getDate() {
		return date;
	}
	public void setDate(Date date) {
		this.date = date;
	}
	
	
}
