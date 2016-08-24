<%@ page language="java" pageEncoding="UTF-8"%>
<%@ include file="../../base.jsp"%>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
	<title></title>
	<script type="text/javascript" src="${ctx}/staticfile/js/datepicker/WdatePicker.js"></script>
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
    用户新增
  </div> 
  
<div>


<div class="eXtremeTable" >
<table id="ec_table" class="tableRegion" width="98%" >
	<tr class="odd">
		<td>所属部门：</td>
		<td>
			<select name="deptId">
				<option value="">--请选择--</option>
				<c:forEach items="${deptList}" var="d">
					<option value="${d.deptId}">${d.deptName}</option>
				</c:forEach>
			</select>
		</td>
		<td>登录名：</td>
		<td><input type="text" name="userName"/></td>
		<td>登录密码：<input type="text" name="passWord"/></td>
	</tr>	
	<tr class="odd">
		<td>真实姓名：</td>
		<td><input type="text" name="name"/></td>
		<td>身份证号：</td>
		<td><input type="text" name="cardNo"/></td>
	</tr>	
	<tr class="odd">
		<td>直属领导：</td>
		<td>
			<select name="managerId">
				<option>--请选择--</option>
				<c:forEach items="${userList}" var="user">
					<option value="${user.userInfo.userInfoId}">${user.userInfo.name}</option>
				</c:forEach>
			</select>
		</td>
		<td>入职时间：</td>
		<td>
			<input type="text" style="width:90px;" name="joinDate"
	               onclick="WdatePicker({el:this,isShowOthers:true,dateFmt:'yyyy-MM-dd'});"/>		
		</td>
	</tr>			
		<tr class="odd">
		<td>薪水：</td>
		<td><input type="text" name="salary"/></td>
		<td>出生年月：</td>
		<td>
			<input type="text" style="width:90px;" name="birthday" readonly
	               onclick="WdatePicker({el:this,isShowOthers:true,dateFmt:'yyyy-MM-dd'});"/>		
		</td>
	</tr>	
	<tr class="odd">
		
		<td>岗位</td>
		<td><input type="text" name="station"/></td>
	</tr>		
	<tr class="odd">
		<td>电话：</td>
		<td><input type="text" name="telephone"/></td>
		<td>等级</td>
		
	</tr>	
	<tr class="odd">
		<td>备注：</td>
		<td><textarea style="height:120px;" name="remark"></textarea></td>
		
</tr>		
</table>
</div>
 
</div>

 
</form>
</body>
</html>

