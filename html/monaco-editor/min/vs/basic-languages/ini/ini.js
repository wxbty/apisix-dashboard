define("vs/basic-languages/ini/ini",["require","require"],(e=>{var n=(()=>{var e=Object.defineProperty,n=Object.getOwnPropertyDescriptor,t=Object.getOwnPropertyNames,r=Object.prototype.hasOwnProperty,o=n=>e(n,"__esModule",{value:!0}),s=(n,t)=>{for(var r in t)e(n,r,{get:t[r],enumerable:!0})},i=(o,s,i,a)=>{if(s&&"object"==typeof s||"function"==typeof s)for(let c of t(s))!r.call(o,c)&&(i||"default"!==c)&&e(o,c,{get:()=>s[c],enumerable:!(a=n(s,c))||a.enumerable});return o},a=(e=>(n,t)=>e&&e.get(n)||(t=i(o({}),n,1),e&&e.set(n,t),t))("undefined"!=typeof WeakMap?new WeakMap:0),c={};s(c,{conf:()=>l,language:()=>p});var l={comments:{lineComment:"#"},brackets:[["{","}"],["[","]"],["(",")"]],autoClosingPairs:[{open:"{",close:"}"},{open:"[",close:"]"},{open:"(",close:")"},{open:'"',close:'"'},{open:"'",close:"'"}],surroundingPairs:[{open:"{",close:"}"},{open:"[",close:"]"},{open:"(",close:")"},{open:'"',close:'"'},{open:"'",close:"'"}]},p={defaultToken:"",tokenPostfix:".ini",escapes:/\\(?:[abfnrtv\\"']|x[0-9A-Fa-f]{1,4}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8})/,tokenizer:{root:[[/^\[[^\]]*\]/,"metatag"],[/(^\w+)(\s*)(\=)/,["key","","delimiter"]],{include:"@whitespace"},[/\d+/,"number"],[/"([^"\\]|\\.)*$/,"string.invalid"],[/'([^'\\]|\\.)*$/,"string.invalid"],[/"/,"string",'@string."'],[/'/,"string","@string.'"]],whitespace:[[/[ \t\r\n]+/,""],[/^\s*[#;].*$/,"comment"]],string:[[/[^\\"']+/,"string"],[/@escapes/,"string.escape"],[/\\./,"string.escape.invalid"],[/["']/,{cases:{"$#==$S2":{token:"string",next:"@pop"},"@default":"string"}}]]}};return a(c)})();return n}));