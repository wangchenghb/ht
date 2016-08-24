<%@ page language="java" pageEncoding="UTF-8"%>
<%@ include file="../../base.jsp"%>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
	
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
    部门新增
  </div> 
 
<div>


<div class="eXtremeTable" >
<table id="ec_table" class="tableRegion" width="98%" >
	
</table>
</div>
	<tr>
		<td>部门名称<input type="text" name="deptName"></input></td>
		<td>父部门
		<select name="parentId" >
			<option>请选择</option>
			<c:forEach items="${dateList }" var="dept">
			
				<option value="${dept.deptId }"  >${dept.deptName }</option>
				
			</c:forEach>
		</select>
		</td>
	</tr>
 
</div>
 
 
</form>
</body>
</html>

