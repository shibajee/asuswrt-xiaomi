<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<html xmlns:v>
<head>
<meta http-equiv="X-UA-Compatible" content="IE=Edge"/>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta HTTP-EQUIV="Pragma" CONTENT="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="-1">
<link rel="shortcut icon" href="images/favicon.png">
<link rel="icon" href="images/favicon.png">
<title><#Web_Title#> - FileFlex</title>
<link rel="stylesheet" type="text/css" href="index_style.css"> 
<link rel="stylesheet" type="text/css" href="form_style.css">
<link rel="stylesheet" type="text/css" href="other.css">
<link rel="stylesheet" type="text/css" href="app_installation.css">
<script type="text/javascript" src="/state.js"></script>
<script type="text/javascript" src="/general.js"></script>
<script type="text/javascript" src="/popup.js"></script>
<script type="text/javascript" src="/help.js"></script>
<script type="text/javascript" src="/validator.js"></script>
<script type="text/javascript" src="/disk_functions.js"></script>
<script language="JavaScript" type="text/javascript" src="/js/jquery.js"></script>
<script type="text/javascript" src="/switcherplugin/jquery.iphone-switch.js"></script>
<script type="text/javascript" src="/form.js"></script>
<script type="text/javascript" src="/js/httpApi.js"></script>
<style>
.actionBg{
	margin-left: 15px;
	display: none;
}
.fileflex_icon{
	position: relative;
	background-image: url(images/New_ui/USBExt/app_list_active.svg);
	background-size: cover;
	background-repeat: no-repeat;
	background-position: 0% 63%;
	width: 80px;
	height: 80px;
	margin: 0 auto;
}
.fileflex_icon::before{
	content: "";
	position: absolute;
	top: -20px;
	right: -20px;
	background-image: url(images/New_ui/USBExt/circle.svg);
	background-size: cover;
	background-position: 0% 100%;
	width: 120px;
	height: 120px;
}
.text_link{
	text-decoration: underline;
	cursor: pointer;
	font-weight: bolder;
}
</style>
<script>
var apps_array = <% apps_info("asus"); %>;
window.onresize = function() {
	if(document.getElementById("folderTree_panel").style.display == "block") {
		cal_panel_block("folderTree_panel", 0.25);
	}
} 

function initial(){
	show_menu();

	var fileflex_idx = apps_array.getIndexByValue2D("fileflex");
	if(fileflex_idx[1] != -1 && fileflex_idx != -1) {
		var install = apps_array[fileflex_idx[0]][3];
		if(install == "no")
			$(".actionBg.init").show();
		else
			$(".actionBg.installed").show();
	}
	else
		$(".actionBg.init").show();
}
function selPartition(){
	show_partition();
	cal_panel_block("folderTree_panel", 0.25);
	$("#folderTree_panel").fadeIn(300);
}
function cancel_folderTree(){
	$("#folderTree_panel").fadeOut(300);
}
function show_partition(){
 	require(['/require/modules/diskList.js?hash=' + Math.random().toString()], function(diskList){
		var htmlcode = "";
		var mounted_partition = 0;
		
		htmlcode += '<table align="center" style="margin:auto;border-collapse:collapse;">';

 		var usbDevicesList = diskList.list();
		for(var i=0; i < usbDevicesList.length; i++){
			for(var j=0; j < usbDevicesList[i].partition.length; j++){
				var all_accessable_size = simpleNum(usbDevicesList[i].partition[j].size-usbDevicesList[i].partition[j].used);
				var all_total_size = simpleNum(usbDevicesList[i].partition[j].size);

				if(usbDevicesList[i].partition[j].status== "unmounted")
					continue;

				if(usbDevicesList[i].partition[j].isAppDev){
					if(all_accessable_size > 1)
						htmlcode += '<tr style="cursor:pointer;" onclick="setPart(\'install\', \''+ usbDevicesList[i].partition[j].mountPoint +'\');"><td class="app_table_radius_left"><div class="iconUSBdisk"></div></td><td class="app_table_radius_right" style="width:250px;">\n';
					else
						htmlcode += '<tr><td class="app_table_radius_left"><div class="iconUSBdisk_noquota"></div></td><td class="app_table_radius_right" style="width:250px;">\n';
					htmlcode += '<div class="app_desc"><b>'+ usbDevicesList[i].partition[j].partName + ' <span style="color:#FC0;">(active)</span></b></div>';
				}
				else{
					if(all_accessable_size > 1)
						htmlcode += '<tr style="cursor:pointer;" onclick="setPart(\'switch\', \''+ usbDevicesList[i].partition[j].mountPoint +'\');"><td class="app_table_radius_left"><div class="iconUSBdisk"></div></td><td class="app_table_radius_right" style="width:250px;">\n';
					else
						htmlcode += '<tr><td class="app_table_radius_left"><div class="iconUSBdisk_noquota"></div></td><td class="app_table_radius_right" style="width:250px;">\n';
					htmlcode += '<div class="app_desc"><b>'+ usbDevicesList[i].partition[j].partName + '</b></div>'; 
				}

				if(all_accessable_size > 1)
					htmlcode += '<div class="app_desc"><#Availablespace#>: <b>'+ all_accessable_size+" GB" + '</b></div>'; 
				else
					htmlcode += '<div class="app_desc"><#Availablespace#>: <b>'+ all_accessable_size+" GB <span style=\'color:#FFCC00\'>(Disk quota can not less than 1GB)" + '</span></b></div>';

				htmlcode += '<div class="app_desc"><#Totalspace#>: <b>'+ all_total_size+" GB" + '</b></div>'; 
				htmlcode += '</div><br/><br/></td></tr>\n';
				mounted_partition++;
			}
		}

		if(mounted_partition == 0)
			htmlcode += '<tr height="300px"><td colspan="2"><span class="app_name" style="line-height:100%"><#no_usb_found#></span></td></tr>\n';

		document.getElementById("partition_div").innerHTML = htmlcode;
	});
}
function setPart(_act, _part){
	apps_form(_act, "fileflex", _part);
}

function createAcc(){
	window.open('https://asus.fileflex.com/fbweb/app/public/view/register', '_blank');
}
function loginAcc(){
	window.open('https://asus.fileflex.com', '_blank');
}
function apps_form(_act, _name, _flag){
	cookie.set("apps_last", _name, 1000);
	document.app_form.apps_action.value = _act;
	document.app_form.apps_name.value = _name;
	document.app_form.apps_flag.value = _flag;
	document.app_form.submit();
}
function check_usb_app_dev(){
	get_app_dev_info(function(usbAppDevInfo){
		if(usbAppDevInfo.hasAppDev){
			if(usbAppDevInfo.availableSize)
				apps_form("install", "fileflex", usbAppDevInfo.mountPoint);
			else
				alert("Disk quota can not less than 1GB");/* untranslated */
		}
		else
			selPartition();
	});
}
</script>
</head>

<body onload="initial();" onunLoad="return unload_body();" class="bg">
<div id="TopBanner"></div>
<!-- floder tree-->
<div id="folderTree_panel" class="panel_folder">
	<table>
		<tr>
			<td>
				<div style="width:450px;font-family:Arial;font-size:13px;font-weight:bolder; margin-top:23px;margin-left:30px;"><#DM_Install_partition#> :</div>
			</td>
		</tr>
	</table>
	<div id="partition_div" class="folder_tree" style="margin-top:15px;height:335px;">
		<#no_usb_found#>
	</div>
	<div style="background-image:url(images/Tree/bg_02.png);background-repeat:no-repeat;height:90px;margin-top:5px;">
		<input class="button_gen" type="button" style="margin-left:40%;margin-top:18px;" onclick="cancel_folderTree();" value="<#CTL_Cancel#>">
	</div>
</div>

<div id="hiddenMask" class="popup_bg">
	<table cellpadding="5" cellspacing="0" id="dr_sweet_advise" class="dr_sweet_advise" align="center">
		<tr>
			<td>
				<div class="drword" id="drword" style="height:110px;"><#Main_alert_proceeding_desc4#> <#Main_alert_proceeding_desc1#>...
					<br/>
					<br/>
				</div>
				<div class="drImg"><img src="images/alertImg.png"></div>
				<div style="height:70px;"></div>
			</td>
		</tr>
	</table>
<!--[if lte IE 6.5]><iframe class="hackiframe"></iframe><![endif]-->
</div>

<div id="Loading" class="popup_bg"></div>
<iframe name="hidden_frame" id="hidden_frame" src="" width="0" height="0" frameborder="0"></iframe>
<form method="post" name="app_form" action="/APP_Installation.asp">
<input type="hidden" name="preferred_lang" value="<% nvram_get("preferred_lang"); %>" disabled>
<input type="hidden" name="firmver" value="<% nvram_get("firmver"); %>" disabled>
<input type="hidden" name="apps_action" value="">
<input type="hidden" name="apps_name" value="">
<input type="hidden" name="apps_flag" value="">
</form>
<form method="post" name="form" id="ruleForm" action="/start_apply.htm" target="hidden_frame" autocomplete="off">
<input type="hidden" name="productid" value="<% nvram_get("productid"); %>">
<input type="hidden" name="current_page" value="fileflex.asp">
<input type="hidden" name="next_page" value="fileflex.asp">
<input type="hidden" name="modified" value="0">
<input type="hidden" name="action_mode" value="apply">
<input type="hidden" name="action_script" value="">
<input type="hidden" name="action_wait" value="5">
<input type="hidden" name="preferred_lang" id="preferred_lang" value="<% nvram_get("preferred_lang"); %>">
<input type="hidden" name="firmver" value="<% nvram_get("firmver"); %>">

<table class="content" align="center" cellpadding="0" cellspacing="0">
	<tr>
		<td width="17">&nbsp;</td>
		<!--=====Beginning of Main Menu=====-->
		<td valign="top" width="202">
			<div id="mainMenu"></div>
			<div id="subMenu"></div>
		</td>
		<td valign="top">
			<div id="tabMenu" class="submenuBlock"></div>
			<!--===================================Beginning of Main Content===========================================-->
			<table width="98%" border="0" align="left" cellpadding="0" cellspacing="0">
				<tr>
					<td align="left" valign="top">
						<table width="760px" border="0" cellpadding="5" cellspacing="0" class="FormTitle" id="FormTitle" style="border-radius:3px;">
							<tbody>
								<tr>
									<td bgcolor="#4D595D" valign="top">
										<div>&nbsp;</div>
										<div>
											<table width="100%">
												<tr>
													<td align="left">
														<span class="formfonttitle">FileFlex Connector</span><!-- untranslated -->
													</td>
													<td align="right">
														<img onclick="go_setting('/APP_Installation.asp')" align="right" style="cursor:pointer;position:absolute;margin-left:-40px;margin-top:-30px;" title="Back to USB Extension" src="/images/backprev.png" onMouseOver="this.src='/images/backprevclick.png'" onMouseOut="this.src='/images/backprev.png'">
													</td>
												</tr>
											</table>
										</div>
										<div style="margin:5px;" class="splitLine"></div>
										<div class="formfontdesc" style="line-height:20px;font-style:italic;font-size: 14px;">
											<table>
												<tr>
													<td style="text-align:center;width:200px;">
														<div class="fileflex_icon"></div>
													</td>
													<td>
														FileFlex provides the cloud functionality of secure remote access, sharing and streaming to the router's USB attached storage or the storage of router-networked devices from a smart phone, tablet or remote computer. It also provides automatic back up of photos and videos from smart phones and tablets to your router's USB attached storage or the storage of router-networked devices.<!-- untranslated -->
														<br>
														<a id="faq" href="https://fileflex.com/support/faqs/" target="_blank" style="text-decoration:underline;">FileFlex FAQ</a><!-- untranslated -->
													</td>
												</tr>
											</table>
										</div>
										<br>
										<div class="actionBg init">
											<div class="formfontdesc">
												Click [ Install ] button to download and install FileFlex connector to the router.<!-- untranslated -->
												<br>
												Please create a FileFlex customer account after finishing your installation.<!-- untranslated -->
											</div>
											<input class="button_gen" onclick="check_usb_app_dev();" type="button" value="<#Excute#>"/>
										</div>
										<div class="actionBg installed">
											<div class="formfontdesc" style="font-size:14px;">
												Next Steps : Click <span class="text_link" onclick="createAcc();"><#btn_go#></span> to create a FileFlex account.<!-- untranslated -->
											</div>
											<input class="button_gen" onclick="createAcc();" type="button" value="<#btn_go#>"/>
											<br><br>
											<div style="font-style:italic;">
												<div class="formfontdesc">
													If you have already a FileFlex account click <span class="text_link" onclick="loginAcc();">here</span> to login.<!-- untranslated -->
												</div>
												<div class="formfontdesc">
													To stop FileFlex service, click <span class="text_link" onclick="apps_form('enable','fileflex','no');" >Disable</span> to temporarily stop the service or click <span class="text_link" onclick="apps_form('remove','fileflex','');">Uninstall</span> to remove the connector. You can re-install FileFlex whenever you need the function.<!-- untranslated -->
												</div>
											</div>
										</div>
									</td>
								</tr>
							</tbody>
						</table>
					</td>
				</tr>
			</table>
			<!--===================================End of Main Content===========================================-->
		</td>
		<td width="10" align="center" valign="top">&nbsp;</td>
	</tr>
</table>
</form>
<div id="footer"></div>
</body>
</html>
