var __awaiter=this&&this.__awaiter||function(e,o,t,n){function r(e){return e instanceof t?e:new t((function(o){o(e)}))}return new(t||(t=Promise))((function(t,i){function c(e){try{s(n.next(e))}catch(o){i(o)}}function m(e){try{s(n["throw"](e))}catch(o){i(o)}}function s(e){e.done?t(e.value):r(e.value).then(c,m)}s((n=n.apply(e,o||[])).next())}))};import{CancellationToken}from"../../../../base/common/cancellation.js";import{assertType}from"../../../../base/common/types.js";import{URI}from"../../../../base/common/uri.js";import{ITextModelService}from"../../../common/services/resolverService.js";import{IOutlineModelService}from"./outlineModel.js";import{CommandsRegistry}from"../../../../platform/commands/common/commands.js";CommandsRegistry.registerCommand("_executeDocumentSymbolProvider",(function(e,...o){return __awaiter(this,void 0,void 0,(function*(){const[t]=o;assertType(URI.isUri(t));const n=e.get(IOutlineModelService),r=e.get(ITextModelService),i=yield r.createModelReference(t);try{return(yield n.getOrCreate(i.object.textEditorModel,CancellationToken.None)).getTopLevelSymbols()}finally{i.dispose()}}))}));