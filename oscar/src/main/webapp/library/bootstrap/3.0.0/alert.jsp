<!DOCTYPE html>
<%--

    Copyright (c) 2001-2002. Department of Family Medicine, McMaster University. All Rights Reserved.
    This software is published under the GPL GNU General Public License.
    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

    This software was written for the
    Department of Family Medicine
    McMaster University
    Hamilton
    Ontario, Canada

--%>
<html>
  <head>
    <title>Bootstrap 101 Alerts Template</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <!-- Bootstrap -->
    <link href="<%=request.getContextPath() %>/library/bootstrap/3.0.0/css/bootstrap.min.css" rel="stylesheet" media="screen">

    <!-- HTML5 shim and Respond.js IE8 support of HTML5 elements and media queries -->
    <!--[if lt IE 9]>
      <script src="<%=request.getContextPath() %>/library/bootstrap/3.0.0/assets/js/html5shiv.js"></script>
      <script src="<%=request.getContextPath() %>/library/bootstrap/3.0.0/assets/js/respond.min.js"></script>
    <![endif]-->


  </head>
  <body>

    <div class="container">


	    	<h1>Hello, Alerts! <small><a href="index.jsp">view example list</a></small></h1>

      <div class="alert alert-warning fade in">
        <button type="button" class="close" data-dismiss="alert" aria-hidden="true">x</button>
        <strong>Holy warning!</strong> example text to display to user.
      </div>

      <div class="alert alert-success fade in">
        <button type="button" class="close" data-dismiss="alert" aria-hidden="true">x</button>
        <strong>Holy success!</strong> example text to display to user.
      </div>

      <div class="alert alert-danger fade in">
        <button type="button" class="close" data-dismiss="alert" aria-hidden="true">x</button>
        <strong>Holy danger!</strong> example text to display to user.
      </div>

      <div class="alert alert-info fade in">
        <button type="button" class="close" data-dismiss="alert" aria-hidden="true">x</button>
        <strong>Holy info!</strong> example text to display to userd.
      </div>

    </div><!-- /.container -->


    <!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->
    <script src="<%=request.getContextPath() %>/js/jquery-1.12.3.js"></script>
        <script src="<%=request.getContextPath() %>/library/jquery/jquery-migrate-1.4.1.js"></script>
    <!-- Include all compiled plugins (below), or include individual files as needed -->
    <script src="<%=request.getContextPath() %>/library/bootstrap/3.0.0/js/bootstrap.min.js"></script>
  </body>
</html>
