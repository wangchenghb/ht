package pojo;
/**
 * 对应的module_p表	权限表
 * @author tarena
 *
 */

public class Module extends BasePojo{
	private String moduleId;
	private String parentId;
	private String name;
	private int ctype;
	private int state;
	private int orderNo;
	private String remark;
	
	
	private String checked;
	
	
	
	public String getChecked() {
		return checked;
	}

	public void setChecked(String checked) {
		this.checked = checked;
	}

	public String getId(){
		return moduleId;
	}
	
	public String getpId(){
		return parentId;
	}
	
	
	public String getModuleId() {
		return moduleId;
	}
	public void setModuleId(String moduleId) {
		this.moduleId = moduleId;
	}
	public String getParentId() {
		return parentId;
	}
	public void setParentId(String parentId) {
		this.parentId = parentId;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public int getCtype() {
		return ctype;
	}
	public void setCtype(int ctype) {
		this.ctype = ctype;
	}
	public int getState() {
		return state;
	}
	public void setState(int state) {
		this.state = state;
	}
	public int getOrderNo() {
		return orderNo;
	}
	public void setOrderNo(int orderNo) {
		this.orderNo = orderNo;
	}
	public String getRemark() {
		return remark;
	}
	public void setRemark(String remark) {
		this.remark = remark;
	}
	
	
}
