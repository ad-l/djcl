
 // -------------------------------------------------------
 // schema =
 // | {type: "string" | "number" | "boolean", props:[]}
 // | {type: "array", props: prop array[1]}
 // | {type: "object", props: prop array}
 // prop = {name: string, value: schema}
 // -------------------------------------------------------
 // Example:
 // s = DJSON.stringify({a: 1, b:"ok", c:[1,2,3]},
 //   t = {type:"object", props:[
 //    {name:"a",value:{type:"number", props:[]}},
 //    {name:"b",value:{type:"string", props:[]}},
 //    {name:"c",value:{type:"array", props:[
 //       {name:"3",value:{type:"number", props:[]}}
 //     ]}}
 //   ]}
 // );
 // o = {a:0, b:"", c:[0,0,0]};
 // DJSON.parse(s, o, t);
 // DJSON.stringify(o, t) == s
 // -------------------------------------------------------

 var DJSON =
 {
  stringify: function s(obj, schema)
  {
   var p = schema.props, res = "", i = 0, j = 0,
       n = "", m = 0, min = function(a,b){return a<b?a:b};

   switch(schema.type)
   {
    case "object":
     res = "{";
     for(i=0; i<p.length; i++)
     {
      n = p[i].name;
      res += '"'+n+'":'+s(obj[n], p[i].value);
      if(i != p.length-1) res+=',';
     }
     return res+'}';
    break;

    case "array":
     for(j = 0; j < p.length; j++)
     {
      for(i = 0, res = '[', m = min(obj.length, +(p[j].name)|0); i < m; i++)
      {
       res += s(obj[i],p[j].value);
       if(i != m-1) res+=',';
      }
      return res+']';
     }
     return '[]';
    break;

    case "string":
     for(i=0, res='"'; i<obj.length; i++)
     {
      if(obj[i] == "\\" || obj[i] == '"') res+="\\";
      res += obj[i];
     }
     return res+'"';
    break;

    case "number":
     return obj+'';
    break;

    case "boolean":
     return obj ? 'true' : 'false';
    break;
   }
  },

  parse: function(s, obj, schema)
  {
   var offset = -1, n = s.length;
   var sbuffer = "", nbuffer = 0, bbuffer = false;
   var min = function(a,b){return a<b?a:b};
   var is_space = function(s) {
    switch(s){ case ' ': case '\t': case '\r': case '\n': return true; }
    return false;
   };

   var typedparse = function p(o,schema)
   {
    var st = 0, buf = '', i = 0, j = 0, c = '',
        flag = false, props = [];

    switch(schema.type)
    {
     case "object":
      props = schema.props;
      st = 0; i = 0;
      while(offset++ < n)
      {
       c = s[offset];
       switch(st)
       {
        case 0: // Initial
         if(c == '{') st = 1;
         else if(is_space(c)) continue;
         else throw false;
        break;
        case 1: // Property expected
         if(is_space(c)) continue;
         if(i >= props.length && c == '}') return;
         offset--;
         p({},{type:"string", props:[]});
         if(sbuffer != props[i].name) throw false;
         st = 2;
        break;
        case 2: // Correct prop name
         if(is_space(c)) continue;
         else if(c == ':') st = 3;
         else throw false;
        break;
        case 3: // Value
         if(is_space(c)) continue;
         offset--;
         p(o[props[i].name], props[i].value);
         switch(props[i].value.type)
         {
          case 'string': o[props[i].name] = sbuffer; break;
          case 'number': o[props[i].name] = nbuffer; break;
          case 'boolean': o[props[i].name] = bbuffer; break;
         }
         st = 4;
        break;
        case 4: // After prop
         if(is_space(c)) continue;
         if(++i == props.length)
          if(c == '}') return; else throw false;
         else
          if(c == ',') st = 1; else throw false;
        break;
       }
      }
      throw false;
     break;

     case "array":
      props = schema.props;
      if(!props.length || !((j=+props[0].name)>0)) throw false;
      st = 0; i = 0; j = min(j, o.length);

      while(offset++ < n)
      {
       c = s[offset];
       switch(st)
       {
        case 0: // Initial
         if(c == '[') st = 1;
         else throw false;
        break;
        case 1: // Element expected
         if(c == ' ') continue;
         if(c == ']') return; // Empty
         offset--;
         p(o[i], props[0].value);
         switch(props[0].value.type)
         {
          case 'string': o[i] = sbuffer; break;
          case 'number': o[i] = nbuffer; break;
          case 'boolean': o[i] = bbuffer; break;
         }
         st = 2;
        break;
        case 2: // After element
         if(c == ' ') continue;
         if(c == ']') return;

         if(++i < j && c == ',') st = 1;
         else throw false;
        break;
       }
      }
      throw false;
     break;

     case "string":
      st = 0;
      while(offset++ < n)
      {
       c = s[offset];
       switch(st)
       {
        case 0: // Initial
         if(c == '"'){ sbuffer = ''; st = 1 }
         else throw false;
        break;
        case 1: // String content
         if(c == "\\") st = 2;
         else if(c == '"') return;
         else sbuffer += c;
        break;
        case 2: // Escape
         if(c == 'n') sbuffer += "\n";
         else if(c == 't') sbuffer += "\t";
         else if(c == 'b') sbuffer += "\b";
         else if(c == 'r') sbuffer += "\r";
         else if(c == 'u') st = 3;
         else sbuffer += c;
         if(st == 2) st--;
        break;
        case 3: // Unicode
         buf += c;
         if(buf.length==4)
         {
          i = +buf;
          if(i==0/0) throw false;
          sbuffer += encoding.fromCharCode(i);
          st = 1;
         }
        break;
       }
      }
      throw false;
     break;

     case "number": // Number parser
      buf = '';
      while(offset++ < n)
      {
       c = s[offset];

       switch(c)
       {
        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
        case '+': case '-': case 'e': case 'E': case '.':
         buf += c;
        continue;
       }
       offset--; break;
      }
      i = +buf;
      if(buf == "" || i+1 == i) throw false;
      nbuffer = i;
     break;

     case "boolean":
      buf = '';
      while(offset++ < n)
      {
       buf += s[offset];
       if(buf == "true"){ bbuffer = true; return; }
       else if(buf == "false"){ bbuffer = false; return; }
       if(buf.length >= 5) throw false;
      }
      throw false;
     break;
    }
   };

   try
   {
    typedparse(obj,schema);
    return true;
   }
   catch(e)
   {
    return false;
   }
  }
 };

