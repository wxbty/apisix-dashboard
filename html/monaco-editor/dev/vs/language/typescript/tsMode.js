define("vs/language/typescript/tsMode",["require"],(e=>{var t=(()=>{var t=Object.create,i=Object.defineProperty,s=Object.getOwnPropertyDescriptor,r=Object.getOwnPropertyNames,n=Object.getPrototypeOf,a=Object.prototype.hasOwnProperty,o=(e,t,s)=>t in e?i(e,t,{enumerable:!0,configurable:!0,writable:!0,value:s}):e[t]=s,l=e=>i(e,"__esModule",{value:!0}),c=(t=>"undefined"!==typeof e?e:"undefined"!==typeof Proxy?new Proxy(t,{get:(t,i)=>("undefined"!==typeof e?e:t)[i]}):t)((function(t){if("undefined"!==typeof e)return e.apply(this,arguments);throw new Error('Dynamic require of "'+t+'" is not supported')})),d=(e,t)=>function(){return t||(0,e[r(e)[0]])((t={exports:{}}).exports,t),t.exports},u=(e,t)=>{for(var s in t)i(e,s,{get:t[s],enumerable:!0})},g=(e,t,n,o)=>{if(t&&"object"===typeof t||"function"===typeof t)for(let l of r(t))a.call(e,l)||!n&&"default"===l||i(e,l,{get:()=>t[l],enumerable:!(o=s(t,l))||o.enumerable});return e},p=(e,s)=>g(l(i(null!=e?t(n(e)):{},"default",!s&&e&&e.__esModule?{get:()=>e.default,enumerable:!0}:{value:e,enumerable:!0})),e),m=(e=>(t,i)=>e&&e.get(t)||(i=g(l({}),t,1),e&&e.set(t,i),i))("undefined"!==typeof WeakMap?new WeakMap:0),f=(e,t,i)=>(o(e,"symbol"!==typeof t?t+"":t,i),i),b=d({"src/fillers/monaco-editor-core-amd.ts"(e,t){var i=p(c("vs/editor/editor.api"));t.exports=i}}),h={};u(h,{Adapter:()=>v,CodeActionAdaptor:()=>j,DefinitionAdapter:()=>O,DiagnosticsAdapter:()=>D,FormatAdapter:()=>W,FormatHelper:()=>H,FormatOnTypeAdapter:()=>V,InlayHintsAdapter:()=>U,Kind:()=>M,LibFiles:()=>C,OccurrencesAdapter:()=>P,OutlineAdapter:()=>N,QuickInfoAdapter:()=>L,ReferenceAdapter:()=>T,RenameAdapter:()=>B,SignatureHelpAdapter:()=>I,SuggestAdapter:()=>A,WorkerManager:()=>y,flattenDiagnosticMessageText:()=>x,getJavaScriptWorker:()=>q,getTypeScriptWorker:()=>G,setupJavaScript:()=>z,setupTypeScript:()=>$});var _={};g(_,p(b()));var y=class{_modeId;_defaults;_configChangeListener;_updateExtraLibsToken;_extraLibsChangeListener;_worker;_client;constructor(e,t){this._modeId=e,this._defaults=t,this._worker=null,this._client=null,this._configChangeListener=this._defaults.onDidChange((()=>this._stopWorker())),this._updateExtraLibsToken=0,this._extraLibsChangeListener=this._defaults.onDidExtraLibsChange((()=>this._updateExtraLibs()))}_stopWorker(){this._worker&&(this._worker.dispose(),this._worker=null),this._client=null}dispose(){this._configChangeListener.dispose(),this._extraLibsChangeListener.dispose(),this._stopWorker()}async _updateExtraLibs(){if(!this._worker)return;const e=++this._updateExtraLibsToken,t=await this._worker.getProxy();this._updateExtraLibsToken===e&&t.updateExtraLibs(this._defaults.getExtraLibs())}_getClient(){if(!this._client){this._worker=_.editor.createWebWorker({moduleId:"vs/language/typescript/tsWorker",label:this._modeId,keepIdleModels:!0,createData:{compilerOptions:this._defaults.getCompilerOptions(),extraLibs:this._defaults.getExtraLibs(),customWorkerPath:this._defaults.workerOptions.customWorkerPath,inlayHintsOptions:this._defaults.inlayHintsOptions}});let e=this._worker.getProxy();this._defaults.getEagerModelSync()&&(e=e.then((e=>this._worker?this._worker.withSyncedResources(_.editor.getModels().filter((e=>e.getLanguageId()===this._modeId)).map((e=>e.uri))):e))),this._client=e}return this._client}getLanguageServiceWorker(...e){let t;return this._getClient().then((e=>{t=e})).then((t=>{if(this._worker)return this._worker.withSyncedResources(e)})).then((e=>t))}},w=c("./monaco.contribution"),S={};function x(e,t,i=0){if("string"===typeof e)return e;if(void 0===e)return"";let s="";if(i){s+=t;for(let e=0;e<i;e++)s+="  "}if(s+=e.messageText,i++,e.next)for(const r of e.next)s+=x(r,t,i);return s}function k(e){return e?e.map((e=>e.text)).join(""):""}S["lib.d.ts"]=!0,S["lib.dom.d.ts"]=!0,S["lib.dom.iterable.d.ts"]=!0,S["lib.es2015.collection.d.ts"]=!0,S["lib.es2015.core.d.ts"]=!0,S["lib.es2015.d.ts"]=!0,S["lib.es2015.generator.d.ts"]=!0,S["lib.es2015.iterable.d.ts"]=!0,S["lib.es2015.promise.d.ts"]=!0,S["lib.es2015.proxy.d.ts"]=!0,S["lib.es2015.reflect.d.ts"]=!0,S["lib.es2015.symbol.d.ts"]=!0,S["lib.es2015.symbol.wellknown.d.ts"]=!0,S["lib.es2016.array.include.d.ts"]=!0,S["lib.es2016.d.ts"]=!0,S["lib.es2016.full.d.ts"]=!0,S["lib.es2017.d.ts"]=!0,S["lib.es2017.full.d.ts"]=!0,S["lib.es2017.intl.d.ts"]=!0,S["lib.es2017.object.d.ts"]=!0,S["lib.es2017.sharedmemory.d.ts"]=!0,S["lib.es2017.string.d.ts"]=!0,S["lib.es2017.typedarrays.d.ts"]=!0,S["lib.es2018.asyncgenerator.d.ts"]=!0,S["lib.es2018.asynciterable.d.ts"]=!0,S["lib.es2018.d.ts"]=!0,S["lib.es2018.full.d.ts"]=!0,S["lib.es2018.intl.d.ts"]=!0,S["lib.es2018.promise.d.ts"]=!0,S["lib.es2018.regexp.d.ts"]=!0,S["lib.es2019.array.d.ts"]=!0,S["lib.es2019.d.ts"]=!0,S["lib.es2019.full.d.ts"]=!0,S["lib.es2019.object.d.ts"]=!0,S["lib.es2019.string.d.ts"]=!0,S["lib.es2019.symbol.d.ts"]=!0,S["lib.es2020.bigint.d.ts"]=!0,S["lib.es2020.d.ts"]=!0,S["lib.es2020.full.d.ts"]=!0,S["lib.es2020.intl.d.ts"]=!0,S["lib.es2020.promise.d.ts"]=!0,S["lib.es2020.sharedmemory.d.ts"]=!0,S["lib.es2020.string.d.ts"]=!0,S["lib.es2020.symbol.wellknown.d.ts"]=!0,S["lib.es2021.d.ts"]=!0,S["lib.es2021.full.d.ts"]=!0,S["lib.es2021.intl.d.ts"]=!0,S["lib.es2021.promise.d.ts"]=!0,S["lib.es2021.string.d.ts"]=!0,S["lib.es2021.weakref.d.ts"]=!0,S["lib.es5.d.ts"]=!0,S["lib.es6.d.ts"]=!0,S["lib.esnext.d.ts"]=!0,S["lib.esnext.full.d.ts"]=!0,S["lib.esnext.intl.d.ts"]=!0,S["lib.esnext.promise.d.ts"]=!0,S["lib.esnext.string.d.ts"]=!0,S["lib.esnext.weakref.d.ts"]=!0,S["lib.scripthost.d.ts"]=!0,S["lib.webworker.d.ts"]=!0,S["lib.webworker.importscripts.d.ts"]=!0,S["lib.webworker.iterable.d.ts"]=!0;var v=class{constructor(e){this._worker=e}_textSpanToRange(e,t){let i=e.getPositionAt(t.start),s=e.getPositionAt(t.start+t.length),{lineNumber:r,column:n}=i,{lineNumber:a,column:o}=s;return{startLineNumber:r,startColumn:n,endLineNumber:a,endColumn:o}}},C=class{constructor(e){this._worker=e,this._libFiles={},this._hasFetchedLibFiles=!1,this._fetchLibFilesPromise=null}_libFiles;_hasFetchedLibFiles;_fetchLibFilesPromise;isLibFile(e){return!!e&&(0===e.path.indexOf("/lib.")&&!!S[e.path.slice(1)])}getOrCreateModel(e){const t=_.Uri.parse(e),i=_.editor.getModel(t);if(i)return i;if(this.isLibFile(t)&&this._hasFetchedLibFiles)return _.editor.createModel(this._libFiles[t.path.slice(1)],"typescript",t);const s=w.typescriptDefaults.getExtraLibs()[e];return s?_.editor.createModel(s.content,"typescript",t):null}_containsLibFile(e){for(let t of e)if(this.isLibFile(t))return!0;return!1}async fetchLibFilesIfNecessary(e){this._containsLibFile(e)&&await this._fetchLibFiles()}_fetchLibFiles(){return this._fetchLibFilesPromise||(this._fetchLibFilesPromise=this._worker().then((e=>e.getLibFiles())).then((e=>{this._hasFetchedLibFiles=!0,this._libFiles=e}))),this._fetchLibFilesPromise}},D=class extends v{constructor(e,t,i,s){super(s),this._libFiles=e,this._defaults=t,this._selector=i;const r=e=>{if(e.getLanguageId()!==i)return;const t=()=>{const{onlyVisible:t}=this._defaults.getDiagnosticsOptions();t?e.isAttachedToEditor()&&this._doValidate(e):this._doValidate(e)};let s;const r=e.onDidChangeContent((()=>{clearTimeout(s),s=window.setTimeout(t,500)})),n=e.onDidChangeAttached((()=>{const{onlyVisible:i}=this._defaults.getDiagnosticsOptions();i&&(e.isAttachedToEditor()?t():_.editor.setModelMarkers(e,this._selector,[]))}));this._listener[e.uri.toString()]={dispose(){r.dispose(),n.dispose(),clearTimeout(s)}},t()},n=e=>{_.editor.setModelMarkers(e,this._selector,[]);const t=e.uri.toString();this._listener[t]&&(this._listener[t].dispose(),delete this._listener[t])};this._disposables.push(_.editor.onDidCreateModel((e=>r(e)))),this._disposables.push(_.editor.onWillDisposeModel(n)),this._disposables.push(_.editor.onDidChangeModelLanguage((e=>{n(e.model),r(e.model)}))),this._disposables.push({dispose(){for(const e of _.editor.getModels())n(e)}});const a=()=>{for(const e of _.editor.getModels())n(e),r(e)};this._disposables.push(this._defaults.onDidChange(a)),this._disposables.push(this._defaults.onDidExtraLibsChange(a)),_.editor.getModels().forEach((e=>r(e)))}_disposables=[];_listener=Object.create(null);dispose(){this._disposables.forEach((e=>e&&e.dispose())),this._disposables=[]}async _doValidate(e){const t=await this._worker(e.uri);if(e.isDisposed())return;const i=[],{noSyntaxValidation:s,noSemanticValidation:r,noSuggestionDiagnostics:n}=this._defaults.getDiagnosticsOptions();s||i.push(t.getSyntacticDiagnostics(e.uri.toString())),r||i.push(t.getSemanticDiagnostics(e.uri.toString())),n||i.push(t.getSuggestionDiagnostics(e.uri.toString()));const a=await Promise.all(i);if(!a||e.isDisposed())return;const o=a.reduce(((e,t)=>t.concat(e)),[]).filter((e=>-1===(this._defaults.getDiagnosticsOptions().diagnosticCodesToIgnore||[]).indexOf(e.code))),l=o.map((e=>e.relatedInformation||[])).reduce(((e,t)=>t.concat(e)),[]).map((e=>e.file?_.Uri.parse(e.file.fileName):null));await this._libFiles.fetchLibFilesIfNecessary(l),e.isDisposed()||_.editor.setModelMarkers(e,this._selector,o.map((t=>this._convertDiagnostics(e,t))))}_convertDiagnostics(e,t){const i=t.start||0,s=t.length||1,{lineNumber:r,column:n}=e.getPositionAt(i),{lineNumber:a,column:o}=e.getPositionAt(i+s),l=[];return t.reportsUnnecessary&&l.push(_.MarkerTag.Unnecessary),t.reportsDeprecated&&l.push(_.MarkerTag.Deprecated),{severity:this._tsDiagnosticCategoryToMarkerSeverity(t.category),startLineNumber:r,startColumn:n,endLineNumber:a,endColumn:o,message:x(t.messageText,"\n"),code:t.code.toString(),tags:l,relatedInformation:this._convertRelatedInformation(e,t.relatedInformation)}}_convertRelatedInformation(e,t){if(!t)return[];const i=[];return t.forEach((t=>{let s=e;if(t.file&&(s=this._libFiles.getOrCreateModel(t.file.fileName)),!s)return;const r=t.start||0,n=t.length||1,{lineNumber:a,column:o}=s.getPositionAt(r),{lineNumber:l,column:c}=s.getPositionAt(r+n);i.push({resource:s.uri,startLineNumber:a,startColumn:o,endLineNumber:l,endColumn:c,message:x(t.messageText,"\n")})})),i}_tsDiagnosticCategoryToMarkerSeverity(e){switch(e){case 1:return _.MarkerSeverity.Error;case 3:return _.MarkerSeverity.Info;case 0:return _.MarkerSeverity.Warning;case 2:return _.MarkerSeverity.Hint}return _.MarkerSeverity.Info}},A=class extends v{get triggerCharacters(){return["."]}async provideCompletionItems(e,t,i,s){const r=e.getWordUntilPosition(t),n=new _.Range(t.lineNumber,r.startColumn,t.lineNumber,r.endColumn),a=e.uri,o=e.getOffsetAt(t),l=await this._worker(a);if(e.isDisposed())return;const c=await l.getCompletionsAtPosition(a.toString(),o);if(!c||e.isDisposed())return;const d=c.entries.map((i=>{let s=n;if(i.replacementSpan){const t=e.getPositionAt(i.replacementSpan.start),r=e.getPositionAt(i.replacementSpan.start+i.replacementSpan.length);s=new _.Range(t.lineNumber,t.column,r.lineNumber,r.column)}const r=[];return-1!==i.kindModifiers?.indexOf("deprecated")&&r.push(_.languages.CompletionItemTag.Deprecated),{uri:a,position:t,offset:o,range:s,label:i.name,insertText:i.name,sortText:i.sortText,kind:A.convertKind(i.kind),tags:r}}));return{suggestions:d}}async resolveCompletionItem(e,t){const i=e,s=i.uri,r=i.position,n=i.offset,a=await this._worker(s),o=await a.getCompletionEntryDetails(s.toString(),n,i.label);return o?{uri:s,position:r,label:o.name,kind:A.convertKind(o.kind),detail:k(o.displayParts),documentation:{value:A.createDocumentationString(o)}}:i}static convertKind(e){switch(e){case M.primitiveType:case M.keyword:return _.languages.CompletionItemKind.Keyword;case M.variable:case M.localVariable:return _.languages.CompletionItemKind.Variable;case M.memberVariable:case M.memberGetAccessor:case M.memberSetAccessor:return _.languages.CompletionItemKind.Field;case M.function:case M.memberFunction:case M.constructSignature:case M.callSignature:case M.indexSignature:return _.languages.CompletionItemKind.Function;case M.enum:return _.languages.CompletionItemKind.Enum;case M.module:return _.languages.CompletionItemKind.Module;case M.class:return _.languages.CompletionItemKind.Class;case M.interface:return _.languages.CompletionItemKind.Interface;case M.warning:return _.languages.CompletionItemKind.File}return _.languages.CompletionItemKind.Property}static createDocumentationString(e){let t=k(e.documentation);if(e.tags)for(const i of e.tags)t+=`\n\n${F(i)}`;return t}};function F(e){let t=`*@${e.name}*`;if("param"===e.name&&e.text){const[i,...s]=e.text;t+=`\`${i.text}\``,s.length>0&&(t+=` \u2014 ${s.map((e=>e.text)).join(" ")}`)}else Array.isArray(e.text)?t+=` \u2014 ${e.text.map((e=>e.text)).join(" ")}`:e.text&&(t+=` \u2014 ${e.text}`);return t}var I=class extends v{signatureHelpTriggerCharacters=["(",","];static _toSignatureHelpTriggerReason(e){switch(e.triggerKind){case _.languages.SignatureHelpTriggerKind.TriggerCharacter:return e.triggerCharacter?e.isRetrigger?{kind:"retrigger",triggerCharacter:e.triggerCharacter}:{kind:"characterTyped",triggerCharacter:e.triggerCharacter}:{kind:"invoked"};case _.languages.SignatureHelpTriggerKind.ContentChange:return e.isRetrigger?{kind:"retrigger"}:{kind:"invoked"};case _.languages.SignatureHelpTriggerKind.Invoke:default:return{kind:"invoked"}}}async provideSignatureHelp(e,t,i,s){const r=e.uri,n=e.getOffsetAt(t),a=await this._worker(r);if(e.isDisposed())return;const o=await a.getSignatureHelpItems(r.toString(),n,{triggerReason:I._toSignatureHelpTriggerReason(s)});if(!o||e.isDisposed())return;const l={activeSignature:o.selectedItemIndex,activeParameter:o.argumentIndex,signatures:[]};return o.items.forEach((e=>{const t={label:"",parameters:[]};t.documentation={value:k(e.documentation)},t.label+=k(e.prefixDisplayParts),e.parameters.forEach(((i,s,r)=>{const n=k(i.displayParts),a={label:n,documentation:{value:k(i.documentation)}};t.label+=n,t.parameters.push(a),s<r.length-1&&(t.label+=k(e.separatorDisplayParts))})),t.label+=k(e.suffixDisplayParts),l.signatures.push(t)})),{value:l,dispose(){}}}},L=class extends v{async provideHover(e,t,i){const s=e.uri,r=e.getOffsetAt(t),n=await this._worker(s);if(e.isDisposed())return;const a=await n.getQuickInfoAtPosition(s.toString(),r);if(!a||e.isDisposed())return;const o=k(a.documentation),l=a.tags?a.tags.map((e=>F(e))).join("  \n\n"):"",c=k(a.displayParts);return{range:this._textSpanToRange(e,a.textSpan),contents:[{value:"```typescript\n"+c+"\n```\n"},{value:o+(l?"\n\n"+l:"")}]}}},P=class extends v{async provideDocumentHighlights(e,t,i){const s=e.uri,r=e.getOffsetAt(t),n=await this._worker(s);if(e.isDisposed())return;const a=await n.getOccurrencesAtPosition(s.toString(),r);return a&&!e.isDisposed()?a.map((t=>({range:this._textSpanToRange(e,t.textSpan),kind:t.isWriteAccess?_.languages.DocumentHighlightKind.Write:_.languages.DocumentHighlightKind.Text}))):void 0}},O=class extends v{constructor(e,t){super(t),this._libFiles=e}async provideDefinition(e,t,i){const s=e.uri,r=e.getOffsetAt(t),n=await this._worker(s);if(e.isDisposed())return;const a=await n.getDefinitionAtPosition(s.toString(),r);if(!a||e.isDisposed())return;if(await this._libFiles.fetchLibFilesIfNecessary(a.map((e=>_.Uri.parse(e.fileName)))),e.isDisposed())return;const o=[];for(let l of a){const e=this._libFiles.getOrCreateModel(l.fileName);e&&o.push({uri:e.uri,range:this._textSpanToRange(e,l.textSpan)})}return o}},T=class extends v{constructor(e,t){super(t),this._libFiles=e}async provideReferences(e,t,i,s){const r=e.uri,n=e.getOffsetAt(t),a=await this._worker(r);if(e.isDisposed())return;const o=await a.getReferencesAtPosition(r.toString(),n);if(!o||e.isDisposed())return;if(await this._libFiles.fetchLibFilesIfNecessary(o.map((e=>_.Uri.parse(e.fileName)))),e.isDisposed())return;const l=[];for(let c of o){const e=this._libFiles.getOrCreateModel(c.fileName);e&&l.push({uri:e.uri,range:this._textSpanToRange(e,c.textSpan)})}return l}},N=class extends v{async provideDocumentSymbols(e,t){const i=e.uri,s=await this._worker(i);if(e.isDisposed())return;const r=await s.getNavigationBarItems(i.toString());if(!r||e.isDisposed())return;const n=(t,i,s)=>{let r={name:i.text,detail:"",kind:K[i.kind]||_.languages.SymbolKind.Variable,range:this._textSpanToRange(e,i.spans[0]),selectionRange:this._textSpanToRange(e,i.spans[0]),tags:[]};if(s&&(r.containerName=s),i.childItems&&i.childItems.length>0)for(let e of i.childItems)n(t,e,r.name);t.push(r)};let a=[];return r.forEach((e=>n(a,e))),a}},M=class{};f(M,"unknown",""),f(M,"keyword","keyword"),f(M,"script","script"),f(M,"module","module"),f(M,"class","class"),f(M,"interface","interface"),f(M,"type","type"),f(M,"enum","enum"),f(M,"variable","var"),f(M,"localVariable","local var"),f(M,"function","function"),f(M,"localFunction","local function"),f(M,"memberFunction","method"),f(M,"memberGetAccessor","getter"),f(M,"memberSetAccessor","setter"),f(M,"memberVariable","property"),f(M,"constructorImplementation","constructor"),f(M,"callSignature","call"),f(M,"indexSignature","index"),f(M,"constructSignature","construct"),f(M,"parameter","parameter"),f(M,"typeParameter","type parameter"),f(M,"primitiveType","primitive type"),f(M,"label","label"),f(M,"alias","alias"),f(M,"const","const"),f(M,"let","let"),f(M,"warning","warning");var K=Object.create(null);K[M.module]=_.languages.SymbolKind.Module,K[M.class]=_.languages.SymbolKind.Class,K[M.enum]=_.languages.SymbolKind.Enum,K[M.interface]=_.languages.SymbolKind.Interface,K[M.memberFunction]=_.languages.SymbolKind.Method,K[M.memberVariable]=_.languages.SymbolKind.Property,K[M.memberGetAccessor]=_.languages.SymbolKind.Property,K[M.memberSetAccessor]=_.languages.SymbolKind.Property,K[M.variable]=_.languages.SymbolKind.Variable,K[M.const]=_.languages.SymbolKind.Variable,K[M.localVariable]=_.languages.SymbolKind.Variable,K[M.variable]=_.languages.SymbolKind.Variable,K[M.function]=_.languages.SymbolKind.Function,K[M.localFunction]=_.languages.SymbolKind.Function;var R,E,H=class extends v{static _convertOptions(e){return{ConvertTabsToSpaces:e.insertSpaces,TabSize:e.tabSize,IndentSize:e.tabSize,IndentStyle:2,NewLineCharacter:"\n",InsertSpaceAfterCommaDelimiter:!0,InsertSpaceAfterSemicolonInForStatements:!0,InsertSpaceBeforeAndAfterBinaryOperators:!0,InsertSpaceAfterKeywordsInControlFlowStatements:!0,InsertSpaceAfterFunctionKeywordForAnonymousFunctions:!0,InsertSpaceAfterOpeningAndBeforeClosingNonemptyParenthesis:!1,InsertSpaceAfterOpeningAndBeforeClosingNonemptyBrackets:!1,InsertSpaceAfterOpeningAndBeforeClosingTemplateStringBraces:!1,PlaceOpenBraceOnNewLineForControlBlocks:!1,PlaceOpenBraceOnNewLineForFunctions:!1}}_convertTextChanges(e,t){return{text:t.newText,range:this._textSpanToRange(e,t.span)}}},W=class extends H{async provideDocumentRangeFormattingEdits(e,t,i,s){const r=e.uri,n=e.getOffsetAt({lineNumber:t.startLineNumber,column:t.startColumn}),a=e.getOffsetAt({lineNumber:t.endLineNumber,column:t.endColumn}),o=await this._worker(r);if(e.isDisposed())return;const l=await o.getFormattingEditsForRange(r.toString(),n,a,H._convertOptions(i));return l&&!e.isDisposed()?l.map((t=>this._convertTextChanges(e,t))):void 0}},V=class extends H{get autoFormatTriggerCharacters(){return[";","}","\n"]}async provideOnTypeFormattingEdits(e,t,i,s,r){const n=e.uri,a=e.getOffsetAt(t),o=await this._worker(n);if(e.isDisposed())return;const l=await o.getFormattingEditsAfterKeystroke(n.toString(),a,i,H._convertOptions(s));return l&&!e.isDisposed()?l.map((t=>this._convertTextChanges(e,t))):void 0}},j=class extends H{async provideCodeActions(e,t,i,s){const r=e.uri,n=e.getOffsetAt({lineNumber:t.startLineNumber,column:t.startColumn}),a=e.getOffsetAt({lineNumber:t.endLineNumber,column:t.endColumn}),o=H._convertOptions(e.getOptions()),l=i.markers.filter((e=>e.code)).map((e=>e.code)).map(Number),c=await this._worker(r);if(e.isDisposed())return;const d=await c.getCodeFixesAtPosition(r.toString(),n,a,l,o);if(!d||e.isDisposed())return{actions:[],dispose:()=>{}};const u=d.filter((e=>0===e.changes.filter((e=>e.isNewFile)).length)).map((t=>this._tsCodeFixActionToMonacoCodeAction(e,i,t)));return{actions:u,dispose:()=>{}}}_tsCodeFixActionToMonacoCodeAction(e,t,i){const s=[];for(const n of i.changes)for(const t of n.textChanges)s.push({resource:e.uri,edit:{range:this._textSpanToRange(e,t.span),text:t.newText}});const r={title:i.description,edit:{edits:s},diagnostics:t.markers,kind:"quickfix"};return r}},B=class extends v{constructor(e,t){super(t),this._libFiles=e}async provideRenameEdits(e,t,i,s){const r=e.uri,n=r.toString(),a=e.getOffsetAt(t),o=await this._worker(r);if(e.isDisposed())return;const l=await o.getRenameInfo(n,a,{allowRenameOfImportPath:!1});if(!1===l.canRename)return{edits:[],rejectReason:l.localizedErrorMessage};if(void 0!==l.fileToRename)throw new Error("Renaming files is not supported.");const c=await o.findRenameLocations(n,a,!1,!1,!1);if(!c||e.isDisposed())return;const d=[];for(const u of c){const e=this._libFiles.getOrCreateModel(u.fileName);if(!e)throw new Error(`Unknown file ${u.fileName}.`);d.push({resource:e.uri,edit:{range:this._textSpanToRange(e,u.textSpan),text:i}})}return{edits:d}}},U=class extends v{async provideInlayHints(e,t,i){const s=e.uri,r=s.toString(),n=e.getOffsetAt({lineNumber:t.startLineNumber,column:t.startColumn}),a=e.getOffsetAt({lineNumber:t.endLineNumber,column:t.endColumn}),o=await this._worker(s);if(e.isDisposed())return null;const l=await o.provideInlayHints(r,n,a),c=l.map((t=>({...t,label:t.text,position:e.getPositionAt(t.position),kind:this._convertHintKind(t.kind)})));return{hints:c,dispose:()=>{}}}_convertHintKind(e){switch(e){case"Parameter":return _.languages.InlayHintKind.Parameter;case"Type":return _.languages.InlayHintKind.Type;default:return _.languages.InlayHintKind.Other}}};function $(e){E=J(e,"typescript")}function z(e){R=J(e,"javascript")}function q(){return new Promise(((e,t)=>{if(!R)return t("JavaScript not registered!");e(R)}))}function G(){return new Promise(((e,t)=>{if(!E)return t("TypeScript not registered!");e(E)}))}function J(e,t){const i=new y(t,e),s=(...e)=>i.getLanguageServiceWorker(...e),r=new C(s);return _.languages.registerCompletionItemProvider(t,new A(s)),_.languages.registerSignatureHelpProvider(t,new I(s)),_.languages.registerHoverProvider(t,new L(s)),_.languages.registerDocumentHighlightProvider(t,new P(s)),_.languages.registerDefinitionProvider(t,new O(r,s)),_.languages.registerReferenceProvider(t,new T(r,s)),_.languages.registerDocumentSymbolProvider(t,new N(s)),_.languages.registerDocumentRangeFormattingEditProvider(t,new W(s)),_.languages.registerOnTypeFormattingEditProvider(t,new V(s)),_.languages.registerCodeActionProvider(t,new j(s)),_.languages.registerRenameProvider(t,new B(r,s)),_.languages.registerInlayHintsProvider(t,new U(s)),new D(r,e,t,s),s}return m(h)})();return t}));