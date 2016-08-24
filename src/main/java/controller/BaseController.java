package controller;

import java.text.SimpleDateFormat;

import org.springframework.beans.propertyeditors.CustomDateEditor;
import org.springframework.web.bind.ServletRequestDataBinder;
import org.springframework.web.bind.annotation.InitBinder;

/**
 * 公有的controller解决日期格式问题
 * @author tarena
 *
 */
public class BaseController {
	//为了让日期格式生效变得更通用，可以建一个BaseController，然后把这个方法写在BaseController里
		//然后，让其他Controller继承BaseController
	@InitBinder
	public void InitBinder(ServletRequestDataBinder binder){
		binder.registerCustomEditor(java.util.Date.class, new CustomDateEditor(new SimpleDateFormat("yyyy-MM-dd"), true));
	
	
	}
}
