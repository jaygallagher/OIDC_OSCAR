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


package oscar.oscarDemographic.pageUtil;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.struts.action.Action;
import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;
import oscar.OscarProperties;

/**
 *
 * @author jay
 */
public class ImportLogDownloadAction extends Action {
   
    public ActionForward execute(ActionMapping mapping, ActionForm form, HttpServletRequest request, HttpServletResponse response) throws FileNotFoundException, IOException {


		String importLog = request.getParameter("importlog");

		String tmpDir = OscarProperties.getInstance().getProperty("TMP_DIR");
		File parent = new File(tmpDir);
		File importLogFile = new File(parent, importLog);
		if (!importLogFile.exists() || !importLogFile.getParent().equals(parent.getAbsolutePath())) {
			// either the file doesn't exist or it's a directory traversal attack.
			throw new FileNotFoundException("Invalid file.");
		}
		InputStream in = new FileInputStream(importLogFile);
		OutputStream out = response.getOutputStream();

		response.setContentType("application/octet-stream");
		response.setHeader("Content-Disposition", "attachment; filename=\""+importLog+"\"" );

		byte[] buf = new byte[1024];
		int len;
		while ((len=in.read(buf)) > 0) out.write(buf,0,len);
		in.close();
		out.close();

		return null;
    }
}