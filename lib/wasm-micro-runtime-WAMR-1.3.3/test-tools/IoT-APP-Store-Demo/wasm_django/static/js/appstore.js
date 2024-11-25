/* Copyright (C) 2019 Intel Corporation.  All rights reserved.
* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
*/

function setDivCenter(divname)
//Center a dom
{
   var Top =($(window).height()-$(divname).height())/2;
   var Left = ($(window).width()-$(divname).width())/2;
   var scrollTop = $(document).scrollTop();
   var scrollLeft = $(document).scrollLeft();
   $(divname).css({posisiton:'absolute','top':Top+scrollTop,'left':Left+scrollLeft});

};
setDivCenter(".deletebox");

function setDivheight(divname)
//set the height of "appbook" to contain all its child elements.
{
   var leng = elist.length + flist.length;
   var heig = 51 * leng;
   $(divname).css({height:'heig'});
};
setDivheight(".appbook");

function setfooterposition(divname)
//Locate footer on the right place
{
   var Top = flist.length* $("#devices").height()+300;
   var scrollTop = $(document).scrollTop();
    if (flist.length >=4){
        $(divname).css({posisiton:'absolute','top':Top+scrollTop});
    }
}
setfooterposition(".footer");

function deleteClick (obj)
//Remove an app from apppstore if clicks the "OK" button
{
    var indexapp = $(obj).attr('class').match(/\d+\b/);
    var removeitem = $(".applic"+indexapp);
    var name=removeitem.find('#appinfo1').text().split(":")[1].trim();
    var version=removeitem.find('#appinfo2').text().split(":")[1].trim();

    if (flist.length >= 1){
        $(".deletebox").fadeIn();
        $(".findapp").html("Are you sure to delete "+name);
        $(".suresbtn").click(function (){
            removeitem.remove();
            $.get("/removeapps/",{'name':name,'version':version},function (ret) {
            console.log(ret);});
            $(".deletebox").fadeOut();
            window.location.href="/appstore/";
                 })
        $(".delsbtn").click(function (){
            $(".deletebox").fadeOut(); })}
};

function upload_file()
//Make sure the uploading file is eligible 
{
    var type = ulist[0];
    console.log(type);
    if (type == "Not a wasm file"){
            alert(type);
            window.location.href="/appstore/";  
            }
    if (type == "This App is preloaded"){
            alert(type);
            window.location.href="/appstore/";  
    }
    if (type == "This App is already uploaded"){
            alert(type);
            window.location.href="/appstore/";  
    }
};
upload_file();


function clone()
//Render a interface that shows all the apps for installing in appstore,
//including preloaded ones and locally uploaded ones.
{
    
    var sourceNode = document.getElementById("applications");
    $("#appinfo1").html("product name : "+ elist[0]['ID']);
    $("#appinfo2").html("product Version : "+ elist[0]['Version']);
    $("#delbutton").attr('class','del0');
    $("#applications").attr('class','applic0');

    
        for (var i=1; i<elist.length; i++)
        {
        var cloneNode= sourceNode.cloneNode(true);
        sourceNode.parentNode.appendChild(cloneNode);
        $("#appinfo1").html("product name : "+ elist[i]['ID']);
        $("#appinfo2").html("product Version : "+ elist[i]['Version']);
        $("#delbutton").attr('class','del'+i);
        $("#applications").attr('class','applic'+i);

        }

        for (var i = elist.length; i< elist.length + flist.length; i++)
        {
        var cloneNode= sourceNode.cloneNode(true);
        sourceNode.parentNode.appendChild(cloneNode);
        $("#appinfo1").html("product name : "+ flist[i - elist.length]['ID']);
        $("#appinfo2").html("product Version : "+ flist[i - elist.length]['Version']);
        $("#lable").html("Custom Apps").css("color","green");
        $("#delbutton").attr('class','del'+i);
        $("#applications").attr('class','applic'+i);

        }

        for(var i = 0; i < elist.length; i++)
        {
            var tmp_node = document.getElementsByClassName("del" + i)[0]
            tmp_node.disabled = true
        }
        
};

clone();

   
