<%@ page language="java" pageEncoding="UTF-8"%>
<%@ include file="../../baselist.jsp"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
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
	<li id="view"><a href="#" onclick="formSubmit('toview','_self');this.blur();">查看</a></li>
	<li id="new"><a href="#" onclick="formSubmit('tocreate','_self');this.blur();">新增</a></li>
	<li id="update"><a href="#" onclick="formSubmit('toupdate','_self');this.blur();">修改</a></li>
	<li id="delete"><a href="#" onclick="formSubmit('delete','_self');this.blur();">删除</a></li>
	<li id="new"><a href="#" onclick="formSubmit('start','_self');this.blur();">启用</a></li>
	<li id="new"><a href="#" onclick="formSubmit('stop','_self');this.blur();">停用</a></li>
	<li id="new"><a href="#" onclick="formSubmit('torole','_self');this.blur();">角色</a></li>
</ul>
  </div>
</div>
</div>
</div>
   
  <div class="textbox-title">
	<img src="../../staticfile/skin/default/images/icon/currency_yen.png"/>
    用户列表
  </div> 
  
<div>


<div class="eXtremeTable" >
<table id="ec_table" class="tableRegion" width="98%" >
	<thead>
	<tr>
		<td class="tableHeader"><input type="checkbox" name="selid" onclick="checkAll('userId',this)"></td>
		<td class="tableHeader">序号</td>
		<td class="tableHeader">登录名</td>
		<td class="tableHeader">部门</td>
		<td class="tableHeader">姓名</td>
		<td class="tableHeader">直属领导</td>
		<td class="tableHeader">身份证号</td>
		<td class="tableHeader">薪水</td>
		<td class="tableHeader">出生年月</td>
		<td class="tableHeader">入职时间</td>
		<td class="tableHeader">状态</td>
	</tr>
	</thead>
	<tbody class="tableBody" >
	
	<c:forEach items="${dataList}" var="o" varStatus="status">
	<tr class="odd" onmouseover="this.className='highlight'" onmouseout="this.className='odd'" >
		<td><input type="checkbox" name="userId" value="${o.userId}"/></td>
		<td>${status.index+1}</td>
		<td>${o.userName}</td>
		<td>${o.dept.deptName}</td>
		<td>${o.userInfo.name}</td>
		<td>${o.userInfo.manager.name }</td>
		<td>${o.userInfo.cardNo}</td>
		<td>${o.userInfo.salary}</td>
		<td>${o.userInfo.birthday}</td>
		<td>${o.userInfo.joinDate}</td>
		<td>
			<c:if test="${o.state==1}"><a href="stop?id=${o.userId}">启用</a></c:if>
			<c:if test="${o.state==0}"><a href="start?id=${o.userId}"><font color="red">停用</font></a></c:if>
		</td>
	</tr>
	</c:forEach>
	
	</tbody>
</table>
</div>
 
</div>
 
 
</form>
</body>
</html>

