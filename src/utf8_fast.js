
/** Speed hack for defensive UTF8 decoding.
 ** Relies on the dirtyness of eval() in ECMA
 ** and its ability to break syntactic scoping
 ** under certain circumstances
 **/

(function()
{
 var hex = encoding.hex,
     eval = (function f(x){
       try{
         if(!x) return f(1);
         var eval = this.eval, flag = false;
         eval("flag = true;");
         if(flag) return eval;
       }
       catch(e){}
     })(0),
     o = "{", t = '"', c = "", i = 0;

 if(typeof eval == "function")
 {
  for(i=0; i<65536; i++)
  {
   c = hex[i>>12&15]+hex[i>>8&15]+hex[i>>4&15]+hex[i&15];
   o += '"\\u'+c+'":'+i+',';
   t += '\\u'+c;
  }
  encoding.utf8_table = eval('('+o+'})');
  encoding.utf8 = eval(t+'"');
  encoding.charCode = function(x){return this.utf8_table[x]};
  encoding.fromCharCode = function(i){return this.utf8[i]};
 }
})();

