<%@ page language="java" pageEncoding="UTF-8"%>
<%@ include file="../../base.jsp"%>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
	<title></title>
	<script type="text/javascript" src="${ctx}/staticfile/js/datepicker/WdatePicker.js"></script>
	
	<style type="text/css">
		span { display:inline-block; width:200px;}
	</style>
</head>

<body>
<form name="icform" method="post">
	<input type="text" name="userId" value="${userId}"/>
	
<div id="menubar">
<div id="middleMenubar">
<div id="innerMenubar">
  <div id="navMenubar">
<ul>
	<li id="save"><a href="#" onclick="formSubmit('role','_self');this.blur();">保存</a></li>
	<li id="back"><a href="#" onclick="history.go(-1);return false;this.blur();">返回</a></li>
</ul>
  </div>
</div>
</div>
</div>
   
  <div class="textbox-title">
	<img src="../../staticfile/skin/default/images/icon/currency_yen.png"/>
   当前用户的角色设置
  </div> 
  
<div>



<div style="padding:50px;">
	${roleHtml}
</div>
 
</div>
 
 
</form>
</body>
</html>

