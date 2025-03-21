/* Copyright (C) 2019 Intel Corporation.  All rights reserved.
* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

/*
 *  Dom Location
 *
 */

 function setDivCenter(divname)
// make qn element center aligned
 {
   var Top =($(window).height()-$(divname).height())/2;
   var Left = ($(window).width()-$(divname).width())/2;
   var scrollTop = $(document).scrollTop();
   var scrollLeft = $(document).scrollLeft();
   $(divname).css({posisiton:'absolute','top':Top+scrollTop,'left':Left+scrollLeft});

};

setDivCenter(".middlebox");
setDivCenter(".deletebox");

function setmain(divname){
// Set the pop-up window of apps for download at the right place
    var x = $('#btn').offset().top;
    var Top = x + $('#btn').height()+15;
    var y = $('#btn').offset().left;
    var Left = y + ($('#btn').width()/2)-($(divname).width()/2);
    console.log(Top,Left)
    $(divname).css({'top':Top,'left':Left});
}
setmain(".main")

/*
 * download apps
 *
 */

function getthis(val)
//Telling background which app to be loaded from appstore_list and to be installed in the current device.
{

    /* Get the ip adress and the port of a device, as well as the application ID to be downloaded on this device*/ 
    var ip,port,name,version;
    var ipArr=$("#IPs").text().split(":");
    ip=ipArr[1];
    var portArr=$("#ports").text().split(":");
    port=portArr[1];
    name = $(val).parent().find("#appsinfo1").text().split(":")[1];
    version = $(val).parent().find("#appsinfo2").text().split(":")[1];
    $(".main").fadeOut();

    for (num in alist){
           if (alist[num]['pname'].trim() == name.trim())
                {alert("This app has been downloaded.");
                 return;}};            
    $("#loading").fadeIn();
    var sNode = document.getElementById("APPS");
    var tempNode= sNode.cloneNode(true);
    sNode.parentNode.appendChild(tempNode);
    $("#appinfo1").html("Product Name : "+ name);
    $("#appinfo2").html("Status : "+"Installing");
    $("#appinfo3").html("Current_Version : "+ version);

    $.get("/appDownload/",{'ip':ip.trim(),'port':port.trim(),'name':name.trim(),},function (ret) {
        var status = $.trim(ret.split(":")[1].split("}")[0]);
        $(".loadapp").html(name+" is downloading now");
        var msg = JSON.parse(status)
        console.log(msg)
        if (JSON.parse(status)=="ok"){
            $(".middlebox").fadeIn();
            $(".sourceapp").fadeOut();
            $("#loading").fadeOut();
            $(".findapp").html("Download "+name +" successfully");
            $(".surebtn").click(function (){
                $(".middlebox").fadeOut();
                 window.location.reload();
                 })}
        else if (JSON.parse(status)=="Fail!"){
            alert("Download failed!");
            $("#loading").fadeOut();
            sNode.remove();
        }
        else {
            alert("Install app failed:" + msg)
            $("#loading").fadeOut();
            sNode.remove();
        }
    })
};

window.onload = function clone()
//Add & Delete apps to the device.
{
   /*Install Apps*/
   var sourceNode = document.getElementById("APPS");
   if (alist.length != 0)
   {
   $("#appinfo1").html("Product Name : "+ alist[0]['pname']);
   $("#appinfo2").html("Status : "+ alist[0]['status']);
   $("#appinfo3").html("Current_Version : "+ alist[0]['current_version']);
   $("#delete").attr('class','delet0');
   $("#APPS").attr('class','app0');
   
   for (var i=1; i<alist.length; i++)
     {
       var cloneNode= sourceNode.cloneNode(true);
       sourceNode.parentNode.appendChild(cloneNode);
       $("#appinfo1").html("Product Name : "+ alist[i]['pname']);
       $("#appinfo2").html("Status : "+ alist[i]['status']);
       $("#appinfo3").html("Current_Version : "+ alist[i]['current_version']);
       $("#delete").attr('class','delet'+i);
       $("#APPS").attr('class','app'+i);
     }
    }
    $("#IPs").html("IP : "+ dlist[0]['IP']);
    $("#ports").html("Port : "+ dlist[0]['Port']);
    $("#installs").html("Installed Apps : "+ dlist[0]['apps']);
    


    $(".mybtn").click(function ()
    {
    /*uninstall apps*/
        var thisitem = $(this).parent().attr('class');
        var indexa = thisitem.match(/\d+\b/);
        var pname = $(".app"+indexa).find('#appinfo1').text();

        var ip,port;
        var ipArr=$("#IPs").text().split(":");
        ip=ipArr[1];
        var portArr=$("#ports").text().split(":");
        port=portArr[1];
    
        var name = pname.split(':')[1].trim();
        $(".deletebox").fadeIn();
        $(".findapp").html("Are you sure to delete "+name);
        $(".suresbtn").click(function (){
                $(".app"+indexa).remove();
                $.get("/appDelete/",{'ip':ip.trim(),'port':port.trim(),"name":pname.split(':')[1].trim()},function (ret) {
            console.log(ret);});
                $(".deletebox").fadeOut();
                 window.location.reload();
                 })
        $(".cancelsbtn").click(function (){
                $(".deletebox").fadeOut(); })
    });

};

function getdownloadapps()
{
/*Acquire apps for download from Appstore simultaneously whenever appstore is updated*/
   if (search_node[0] == "Nothing find"){
       alert(search_node[0])
   }
   if (search_node.length == 1 && search_node[0] != "Nothing find" ){
    $("#appsinfo1").html("Product Name : "+ search_node[0]['ID']);
    $("#appsinfo2").html("Version : "+ search_node[0]['Version']);
   }
   else{
       var sourceNode = document.getElementById("Dapplications");
        if (llist.length != 0)
        {
        $("#appsinfo1").html("Product Name : "+ llist[0]['ID']);
        $("#appsinfo2").html("Version : "+ llist[0]['Version']);
        $("#Dapplications").attr('class','dapp0');
        
        for (var i=1; i<llist.length; i++)
            {
            var cloneNode= sourceNode.cloneNode(true);
            sourceNode.parentNode.appendChild(cloneNode);
            $("#appsinfo1").html("Product Name : "+ llist[i]['ID']);
            $("#appsinfo2").html("Version : "+ llist[i]['Version']);
            $("#Dapplications").attr('class','dapp'+i);
            }
        }};
};

getdownloadapps();

function givevalue(){
    var ip=dlist[0]['IP'].trim();
    var port=dlist[0]['Port'].trim();
    document.getElementById("aa").value = ip;
    document.getElementById("bb").value = port;
    if (open_status == "open"){
        $(".main").fadeIn();
        $(".close").click(function(){
            $(".main").fadeOut();
            var newurl = "?"+"ip="+ip+"&port="+port;
            window.location.href= newurl;});
        $(".mybtn2").click(function(){
            if (alist.length >=3){
                alert("Install app failed: exceed max app installations.")
            }
            $(".main").fadeOut();
            getthis(".mybtn2");
            var newurl = "?"+"ip="+ip+"&port="+port;
            window.location.href= newurl;
   });

    }
}
givevalue();

function popbox(){
/*Open and close the "install apps" window*/
   $(".btn").click(function(){
       $(".main").fadeIn();
   });
   $(".close").click(function(){
       $(".main").fadeOut();
   });
};
popbox();
