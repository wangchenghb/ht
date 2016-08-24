<%@ page language="java" pageEncoding="UTF-8"%>
<%@ include file="../../base.jsp"%>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
	<title></title>
</head>

<body>
<form name="icform" method="post">
	<input type="hidden" name="deptId" value="${dept.deptId}"/>

<div id="menubar">
<div id="middleMenubar">
<div id="innerMenubar">
  <div id="navMenubar">
<ul>
	<li id="save"><a href="#" onclick="formSubmit('update','_self');this.blur();">保存</a></li>
	<li id="back"><a href="#" onclick="history.go(-1);return false;this.blur();">返回</a></li>
</ul>
  </div>
</div>
</div>
</div>
   
  <div class="textbox-title">
	<img src="../../staticfile/skin/default/images/icon/currency_yen.png"/>
    部门修改
  </div> 
  
<div>


<div class="eXtremeTable" >
<table id="ec_table" class="tableRegion" width="98%" >
	<!-- 更新部门名称、上级部门 -->
	<tr>
		<td>部门名称<input type="text" value="${dept.deptName }" name="deptName"></input></td>
		<td>父部门
			<select name="parentId">
				<c:if test="${dept.parentId==null }">
				<option>--请选择--</option>
				</c:if>
				
				<c:forEach items="${dataList }" var="de">
					<c:if test="${dept.parentId!=de.deptId }">
					<option value="${de.deptId }">${de.deptName }</option>
					</c:if>
					
					<c:if test="${dept.parentId==de.deptId }">
					<option value="${de.deptId }" selected="selected">${de.deptName }</option>
					</c:if>
				</c:forEach>
			</select>
		</td>
	</tr>
</table>
</div>
</div>
</form>
</body>
</html>

