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
    角色新增
  </div> 
  
<div>


<div class="eXtremeTable" >
<table id="ec_table" class="tableRegion" width="98%" >
	<tr class="odd">
		<td>名称：</td>
		<td><input type="text" name="name"/></td>
	</tr>	
	<tr class="odd">
		<td>说明：</td>
		<td><textarea name="remark" style="height:100px;"></textarea></td>
	</tr>	
	<tr class="odd">
		<td>排序号</td>
		<td><input type="text" name="orderNo"/></td>
	</tr>		
</table>
</div>
 
</div>
 
 
</form>
</body>
</html>

