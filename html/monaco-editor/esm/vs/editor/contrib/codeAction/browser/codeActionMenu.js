var __decorate=this&&this.__decorate||function(e,o,i,t){var n,r=arguments.length,d=r<3?o:null===t?t=Object.getOwnPropertyDescriptor(o,i):t;if("object"===typeof Reflect&&"function"===typeof Reflect.decorate)d=Reflect.decorate(e,o,i,t);else for(var s=e.length-1;s>=0;s--)(n=e[s])&&(d=(r<3?n(d):r>3?n(o,i,d):n(o,i))||d);return r>3&&d&&Object.defineProperty(o,i,d),d},__param=this&&this.__param||function(e,o){return function(i,t){o(i,t,e)}},__awaiter=this&&this.__awaiter||function(e,o,i,t){function n(e){return e instanceof i?e:new i((function(o){o(e)}))}return new(i||(i=Promise))((function(i,r){function d(e){try{c(t.next(e))}catch(o){r(o)}}function s(e){try{c(t["throw"](e))}catch(o){r(o)}}function c(e){e.done?i(e.value):n(e.value).then(d,s)}c((t=t.apply(e,o||[])).next())}))};import{getDomNodePagePosition}from"../../../../base/browser/dom.js";import{Action,Separator}from"../../../../base/common/actions.js";import{canceled}from"../../../../base/common/errors.js";import{Lazy}from"../../../../base/common/lazy.js";import{Disposable,MutableDisposable}from"../../../../base/common/lifecycle.js";import{Position}from"../../../common/core/position.js";import{CodeActionProviderRegistry}from"../../../common/languages.js";import{codeActionCommandId,CodeActionItem,fixAllCommandId,organizeImportsCommandId,refactorCommandId,sourceActionCommandId}from"./codeAction.js";import{CodeActionCommandArgs,CodeActionKind}from"./types.js";import{IContextMenuService}from"../../../../platform/contextview/browser/contextView.js";import{IKeybindingService}from"../../../../platform/keybinding/common/keybinding.js";class CodeActionAction extends Action{constructor(e,o){super(e.command?e.command.id:e.title,stripNewlines(e.title),void 0,!e.disabled,o),this.action=e}}function stripNewlines(e){return e.replace(/\r\n|\r|\n/g," ")}let CodeActionMenu=class extends Disposable{constructor(e,o,i,t){super(),this._editor=e,this._delegate=o,this._contextMenuService=i,this._visible=!1,this._showingActions=this._register(new MutableDisposable),this._keybindingResolver=new CodeActionKeybindingResolver({getKeybindings:()=>t.getKeybindings()})}get isVisible(){return this._visible}show(e,o,i,t){return __awaiter(this,void 0,void 0,(function*(){const n=t.includeDisabledActions?o.allActions:o.validActions;if(!n.length)return void(this._visible=!1);if(!this._editor.getDomNode())throw this._visible=!1,canceled();this._visible=!0,this._showingActions.value=o;const r=this.getMenuActions(e,n,o.documentation),d=Position.isIPosition(i)?this._toCoords(i):i||{x:0,y:0},s=this._keybindingResolver.getResolver(),c=this._editor.getOption(115);this._contextMenuService.showContextMenu({domForShadowRoot:c?this._editor.getDomNode():void 0,getAnchor:()=>d,getActions:()=>r,onHide:()=>{this._visible=!1,this._editor.focus()},autoSelectFirstItem:!0,getKeyBinding:e=>e instanceof CodeActionAction?s(e.action):void 0})}))}getMenuActions(e,o,i){var t,n;const r=e=>new CodeActionAction(e.action,(()=>this._delegate.onSelectCodeAction(e))),d=o.map(r),s=[...i],c=this._editor.getModel();if(c&&d.length)for(const a of CodeActionProviderRegistry.all(c))a._getAdditionalMenuItems&&s.push(...a._getAdditionalMenuItems({trigger:e.type,only:null===(n=null===(t=e.filter)||void 0===t?void 0:t.include)||void 0===n?void 0:n.value},o.map((e=>e.action))));return s.length&&d.push(new Separator,...s.map((e=>r(new CodeActionItem({title:e.title,command:e},void 0))))),d}_toCoords(e){if(!this._editor.hasModel())return{x:0,y:0};this._editor.revealPosition(e,1),this._editor.render();const o=this._editor.getScrolledVisiblePosition(e),i=getDomNodePagePosition(this._editor.getDomNode()),t=i.left+o.left,n=i.top+o.top+o.height;return{x:t,y:n}}};CodeActionMenu=__decorate([__param(2,IContextMenuService),__param(3,IKeybindingService)],CodeActionMenu);export{CodeActionMenu};export class CodeActionKeybindingResolver{constructor(e){this._keybindingProvider=e}getResolver(){const e=new Lazy((()=>this._keybindingProvider.getKeybindings().filter((e=>CodeActionKeybindingResolver.codeActionCommands.indexOf(e.command)>=0)).filter((e=>e.resolvedKeybinding)).map((e=>{let o=e.commandArgs;return e.command===organizeImportsCommandId?o={kind:CodeActionKind.SourceOrganizeImports.value}:e.command===fixAllCommandId&&(o={kind:CodeActionKind.SourceFixAll.value}),Object.assign({resolvedKeybinding:e.resolvedKeybinding},CodeActionCommandArgs.fromUser(o,{kind:CodeActionKind.None,apply:"never"}))}))));return o=>{if(o.kind){const i=this.bestKeybindingForCodeAction(o,e.getValue());return null===i||void 0===i?void 0:i.resolvedKeybinding}}}bestKeybindingForCodeAction(e,o){if(!e.kind)return;const i=new CodeActionKind(e.kind);return o.filter((e=>e.kind.contains(i))).filter((o=>!o.preferred||e.isPreferred)).reduceRight(((e,o)=>e?e.kind.contains(o.kind)?o:e:o),void 0)}}CodeActionKeybindingResolver.codeActionCommands=[refactorCommandId,codeActionCommandId,sourceActionCommandId,organizeImportsCommandId,fixAllCommandId];