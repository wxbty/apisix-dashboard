define("vs/basic-languages/xml/xml",["require"],(e=>{var t=(()=>{var t=Object.create,n=Object.defineProperty,o=Object.getOwnPropertyDescriptor,a=Object.getOwnPropertyNames,i=Object.getPrototypeOf,r=Object.prototype.hasOwnProperty,l=e=>n(e,"__esModule",{value:!0}),d=(t=>"undefined"!==typeof e?e:"undefined"!==typeof Proxy?new Proxy(t,{get:(t,n)=>("undefined"!==typeof e?e:t)[n]}):t)((function(t){if("undefined"!==typeof e)return e.apply(this,arguments);throw new Error('Dynamic require of "'+t+'" is not supported')})),u=(e,t)=>function(){return t||(0,e[a(e)[0]])((t={exports:{}}).exports,t),t.exports},m=(e,t)=>{for(var o in t)n(e,o,{get:t[o],enumerable:!0})},c=(e,t,i,l)=>{if(t&&"object"===typeof t||"function"===typeof t)for(let d of a(t))r.call(e,d)||!i&&"default"===d||n(e,d,{get:()=>t[d],enumerable:!(l=o(t,d))||l.enumerable});return e},s=(e,o)=>c(l(n(null!=e?t(i(e)):{},"default",!o&&e&&e.__esModule?{get:()=>e.default,enumerable:!0}:{value:e,enumerable:!0})),e),p=(e=>(t,n)=>e&&e.get(t)||(n=c(l({}),t,1),e&&e.set(t,n),n))("undefined"!==typeof WeakMap?new WeakMap:0),f=u({"src/fillers/monaco-editor-core-amd.ts"(e,t){var n=s(d("vs/editor/editor.api"));t.exports=n}}),g={};m(g,{conf:()=>b,language:()=>k});var x={};c(x,s(f()));var b={comments:{blockComment:["\x3c!--","--\x3e"]},brackets:[["<",">"]],autoClosingPairs:[{open:"<",close:">"},{open:"'",close:"'"},{open:'"',close:'"'}],surroundingPairs:[{open:"<",close:">"},{open:"'",close:"'"},{open:'"',close:'"'}],onEnterRules:[{beforeText:new RegExp("<([_:\\w][_:\\w-.\\d]*)([^/>]*(?!/)>)[^<]*$","i"),afterText:/^<\/([_:\w][_:\w-.\d]*)\s*>$/i,action:{indentAction:x.languages.IndentAction.IndentOutdent}},{beforeText:new RegExp("<(\\w[\\w\\d]*)([^/>]*(?!/)>)[^<]*$","i"),action:{indentAction:x.languages.IndentAction.Indent}}]},k={defaultToken:"",tokenPostfix:".xml",ignoreCase:!0,qualifiedName:/(?:[\w\.\-]+:)?[\w\.\-]+/,tokenizer:{root:[[/[^<&]+/,""],{include:"@whitespace"},[/(<)(@qualifiedName)/,[{token:"delimiter"},{token:"tag",next:"@tag"}]],[/(<\/)(@qualifiedName)(\s*)(>)/,[{token:"delimiter"},{token:"tag"},"",{token:"delimiter"}]],[/(<\?)(@qualifiedName)/,[{token:"delimiter"},{token:"metatag",next:"@tag"}]],[/(<\!)(@qualifiedName)/,[{token:"delimiter"},{token:"metatag",next:"@tag"}]],[/<\!\[CDATA\[/,{token:"delimiter.cdata",next:"@cdata"}],[/&\w+;/,"string.escape"]],cdata:[[/[^\]]+/,""],[/\]\]>/,{token:"delimiter.cdata",next:"@pop"}],[/\]/,""]],tag:[[/[ \t\r\n]+/,""],[/(@qualifiedName)(\s*=\s*)("[^"]*"|'[^']*')/,["attribute.name","","attribute.value"]],[/(@qualifiedName)(\s*=\s*)("[^">?\/]*|'[^'>?\/]*)(?=[\?\/]\>)/,["attribute.name","","attribute.value"]],[/(@qualifiedName)(\s*=\s*)("[^">]*|'[^'>]*)/,["attribute.name","","attribute.value"]],[/@qualifiedName/,"attribute.name"],[/\?>/,{token:"delimiter",next:"@pop"}],[/(\/)(>)/,[{token:"tag"},{token:"delimiter",next:"@pop"}]],[/>/,{token:"delimiter",next:"@pop"}]],whitespace:[[/[ \t\r\n]+/,""],[/<!--/,{token:"comment",next:"@comment"}]],comment:[[/[^<\-]+/,"comment.content"],[/-->/,{token:"comment",next:"@pop"}],[/<!--/,"comment.content.invalid"],[/[<\-]/,"comment.content"]]}};return p(g)})();return t}));