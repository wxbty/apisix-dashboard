define("vs/basic-languages/azcli/azcli",["require"],(e=>{var t=(()=>{var e=Object.defineProperty,t=Object.getOwnPropertyDescriptor,n=Object.getOwnPropertyNames,o=Object.prototype.hasOwnProperty,r=t=>e(t,"__esModule",{value:!0}),a=(t,n)=>{for(var o in n)e(t,o,{get:n[o],enumerable:!0})},s=(r,a,s,i)=>{if(a&&"object"===typeof a||"function"===typeof a)for(let l of n(a))o.call(r,l)||!s&&"default"===l||e(r,l,{get:()=>a[l],enumerable:!(i=t(a,l))||i.enumerable});return r},i=(e=>(t,n)=>e&&e.get(t)||(n=s(r({}),t,1),e&&e.set(t,n),n))("undefined"!==typeof WeakMap?new WeakMap:0),l={};a(l,{conf:()=>c,language:()=>f});var c={comments:{lineComment:"#"}},f={defaultToken:"keyword",ignoreCase:!0,tokenPostfix:".azcli",str:/[^#\s]/,tokenizer:{root:[{include:"@comment"},[/\s-+@str*\s*/,{cases:{"@eos":{token:"key.identifier",next:"@popall"},"@default":{token:"key.identifier",next:"@type"}}}],[/^-+@str*\s*/,{cases:{"@eos":{token:"key.identifier",next:"@popall"},"@default":{token:"key.identifier",next:"@type"}}}]],type:[{include:"@comment"},[/-+@str*\s*/,{cases:{"@eos":{token:"key.identifier",next:"@popall"},"@default":"key.identifier"}}],[/@str+\s*/,{cases:{"@eos":{token:"string",next:"@popall"},"@default":"string"}}]],comment:[[/#.*$/,{cases:{"@eos":{token:"comment",next:"@popall"}}}]]}};return i(l)})();return t}));