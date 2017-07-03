var mousex = 0;
var mousey = 0;
var grabx = 0;
var graby = 0;
var orix = 0;
var oriy = 0;
var elex = 0;
var eley = 0;
var algor = 0;
var start = 0;
var dragobj = null;

function falsefunc() { return false; } 

function init() 
{
 document.onmousemove = getMouseXY;
 update();

}


function getMouseXY(e) 
{ 
  if (!e) e = window.event; 
 
  if (e)
  { 
    if (e.pageX || e.pageY)
    { 
      mousex = e.pageX;
      mousey = e.pageY;
      algor = '[e.pageX]';
      if (e.clientX || e.clientY) algor += ' [e.clientX] '
    }
    else if (e.clientX || e.clientY)
    { 
      mousex = e.clientX + document.body.scrollLeft + document.documentElement.scrollLeft;
      mousey = e.clientY + document.body.scrollTop + document.documentElement.scrollTop;
      algor = '[e.clientX]';
      if (e.pageX || e.pageY) algor += ' [e.pageX] '
    }
  }
}

function update(e)
{
  getMouseXY(e); 

}

function grab(context)
{
  document.onmousedown = falsefunc; 
  dragobj = context;
  dragobj.style.zIndex = 10; 
  document.onmousemove = drag;
  document.onmouseup = drop;
  grabx = mousex;
  graby = mousey;
  elex = orix = dragobj.offsetLeft;
  eley = oriy = dragobj.offsetTop;
  update();

}

function drag(e) 
{
  if (dragobj)
  {
    elex = orix + (mousex-grabx);
    eley = oriy + (mousey-graby);
    dragobj.style.position = "absolute";
    dragobj.style.left = (elex).toString(10) + 'px';
    dragobj.style.top  = (eley).toString(10) + 'px';
  }
  update(e);
  return false; 
}

function drop()
{
  if (dragobj)
  {
    dragobj.style.zIndex = 0;
    dragobj = null;
  }

  update();
  document.onmousemove = update;
  document.onmouseup = null;
  document.onmousedown = null;
}


function setVisibility(id, visibility) {

   if (document.elementFromPoint(mousex,mousey) != document.getElementById('foo')) 
   {
	document.getElementById(id).style.display = visibility;
  	
   }

}

function ShowText(text) {
 document.getElementById('foo').innerHTML = text;
 setVisibility("foo","inline");
}


function testfunc(obj) {


 getMouseXY();	
 var l = 'headers_' + obj; 
 document.getElementById('foo').innerHTML = document.getElementById(l).innerHTML;
 document.getElementById('foo').style.display = "inline";
 document.getElementById('foo').style.top= mousey -5 + "px" ;
}

init(); 