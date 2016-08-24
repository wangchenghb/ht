<%@ page language="java" pageEncoding="UTF-8"%>
<%@ include file="../../base.jsp"%>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
	<title></title>
</head>

<body>
<form name="icform" method="post">

<div id="menubar">
<div id="middleMenubar">
<div id="innerMenubar">
  <div id="navMenubar">
<ul>
	<li id="save"><a href="#" onclick="formSubmit('insert','_self');this.blur();">保存</a></li>
	<li id="back"><a href="#" onclick="history.go(-1);return false;this.blur();">返回</a></li>
</ul>
  </div>
</div>
</div>
</div>
   
  <div class="textbox-title">
	<img src="../../staticfile/skin/default/images/icon/currency_yen.png"/>
    模块新增
  </div> 
  
<div>


<div class="eXtremeTable" >
<table id="ec_table" class="tableRegion" width="98%" >
	<tr class="odd">
		<td>父模块：</td>
		<td>
			<select name="parentId">
				<option value="">--请选择--</option>
				<c:forEach items="${moduleList}" var="m">
					<option value="${m.moduleId}">${m.name}</option>
				</c:forEach>
			</select>
		</td>
		<td>权限标识：</td>
		<td><input type="text" name="name"/></td>
	</tr>	
	<tr class="odd">
		<td>类型</td>
		<td>
			<select name="ctype">
				<option value="">--请选择--</option>
				<option value="1">主菜单</option>
				<option value="2">左侧菜单</option>
				<option value="3">按钮</option>
			</select>
		</td>
		
	</tr>		
</table>
</div>
 
</div>
 
 
</form>
</body>
</html>

