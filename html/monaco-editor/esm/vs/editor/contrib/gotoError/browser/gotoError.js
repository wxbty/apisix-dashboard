var __decorate=this&&this.__decorate||function(e,t,o,i){var r,n=arguments.length,s=n<3?t:null===i?i=Object.getOwnPropertyDescriptor(t,o):i;if("object"===typeof Reflect&&"function"===typeof Reflect.decorate)s=Reflect.decorate(e,t,o,i);else for(var a=e.length-1;a>=0;a--)(r=e[a])&&(s=(n<3?r(s):n>3?r(t,o,s):r(t,o))||s);return n>3&&s&&Object.defineProperty(t,o,s),s},__param=this&&this.__param||function(e,t){return function(o,i){t(o,i,e)}},__awaiter=this&&this.__awaiter||function(e,t,o,i){function r(e){return e instanceof o?e:new o((function(t){t(e)}))}return new(o||(o=Promise))((function(o,n){function s(e){try{l(i.next(e))}catch(t){n(t)}}function a(e){try{l(i["throw"](e))}catch(t){n(t)}}function l(e){e.done?o(e.value):r(e.value).then(s,a)}l((i=i.apply(e,t||[])).next())}))};import{Codicon}from"../../../../base/common/codicons.js";import{DisposableStore}from"../../../../base/common/lifecycle.js";import{EditorAction,EditorCommand,registerEditorAction,registerEditorCommand,registerEditorContribution}from"../../../browser/editorExtensions.js";import{ICodeEditorService}from"../../../browser/services/codeEditorService.js";import{Position}from"../../../common/core/position.js";import{Range}from"../../../common/core/range.js";import{EditorContextKeys}from"../../../common/editorContextKeys.js";import{IMarkerNavigationService}from"./markerNavigationService.js";import*as nls from"../../../../nls.js";import{MenuId}from"../../../../platform/actions/common/actions.js";import{IContextKeyService,RawContextKey}from"../../../../platform/contextkey/common/contextkey.js";import{IInstantiationService}from"../../../../platform/instantiation/common/instantiation.js";import{registerIcon}from"../../../../platform/theme/common/iconRegistry.js";import{MarkerNavigationWidget}from"./gotoErrorWidget.js";let MarkerController=class e{constructor(e,t,o,i,r){this._markerNavigationService=t,this._contextKeyService=o,this._editorService=i,this._instantiationService=r,this._sessionDispoables=new DisposableStore,this._editor=e,this._widgetVisible=CONTEXT_MARKERS_NAVIGATION_VISIBLE.bindTo(this._contextKeyService)}static get(t){return t.getContribution(e.ID)}dispose(){this._cleanUp(),this._sessionDispoables.dispose()}_cleanUp(){this._widgetVisible.reset(),this._sessionDispoables.clear(),this._widget=void 0,this._model=void 0}_getOrCreateModel(e){if(this._model&&this._model.matches(e))return this._model;let t=!1;return this._model&&(t=!0,this._cleanUp()),this._model=this._markerNavigationService.getMarkerList(e),t&&this._model.move(!0,this._editor.getModel(),this._editor.getPosition()),this._widget=this._instantiationService.createInstance(MarkerNavigationWidget,this._editor),this._widget.onDidClose((()=>this.close()),this,this._sessionDispoables),this._widgetVisible.set(!0),this._sessionDispoables.add(this._model),this._sessionDispoables.add(this._widget),this._sessionDispoables.add(this._editor.onDidChangeCursorPosition((e=>{var t,o,i;(null===(t=this._model)||void 0===t?void 0:t.selected)&&Range.containsPosition(null===(o=this._model)||void 0===o?void 0:o.selected.marker,e.position)||null===(i=this._model)||void 0===i||i.resetIndex()}))),this._sessionDispoables.add(this._model.onDidChange((()=>{if(!this._widget||!this._widget.position||!this._model)return;const e=this._model.find(this._editor.getModel().uri,this._widget.position);e?this._widget.updateMarker(e.marker):this._widget.showStale()}))),this._sessionDispoables.add(this._widget.onDidSelectRelatedInformation((e=>{this._editorService.openCodeEditor({resource:e.resource,options:{pinned:!0,revealIfOpened:!0,selection:Range.lift(e).collapseToStart()}},this._editor),this.close(!1)}))),this._sessionDispoables.add(this._editor.onDidChangeModel((()=>this._cleanUp()))),this._model}close(e=!0){this._cleanUp(),e&&this._editor.focus()}showAtMarker(e){if(this._editor.hasModel()){const t=this._getOrCreateModel(this._editor.getModel().uri);t.resetIndex(),t.move(!0,this._editor.getModel(),new Position(e.startLineNumber,e.startColumn)),t.selected&&this._widget.showAtMarker(t.selected.marker,t.selected.index,t.selected.total)}}nagivate(t,o){var i,r;return __awaiter(this,void 0,void 0,(function*(){if(this._editor.hasModel()){const n=this._getOrCreateModel(o?void 0:this._editor.getModel().uri);if(n.move(t,this._editor.getModel(),this._editor.getPosition()),!n.selected)return;if(n.selected.marker.resource.toString()!==this._editor.getModel().uri.toString()){this._cleanUp();const s=yield this._editorService.openCodeEditor({resource:n.selected.marker.resource,options:{pinned:!1,revealIfOpened:!0,selectionRevealType:2,selection:n.selected.marker}},this._editor);s&&(null===(i=e.get(s))||void 0===i||i.close(),null===(r=e.get(s))||void 0===r||r.nagivate(t,o))}else this._widget.showAtMarker(n.selected.marker,n.selected.index,n.selected.total)}}))}};MarkerController.ID="editor.contrib.markerController",MarkerController=__decorate([__param(1,IMarkerNavigationService),__param(2,IContextKeyService),__param(3,ICodeEditorService),__param(4,IInstantiationService)],MarkerController);export{MarkerController};class MarkerNavigationAction extends EditorAction{constructor(e,t,o){super(o),this._next=e,this._multiFile=t}run(e,t){var o;return __awaiter(this,void 0,void 0,(function*(){t.hasModel()&&(null===(o=MarkerController.get(t))||void 0===o||o.nagivate(this._next,this._multiFile))}))}}export class NextMarkerAction extends MarkerNavigationAction{constructor(){super(!0,!1,{id:NextMarkerAction.ID,label:NextMarkerAction.LABEL,alias:"Go to Next Problem (Error, Warning, Info)",precondition:void 0,kbOpts:{kbExpr:EditorContextKeys.focus,primary:578,weight:100},menuOpts:{menuId:MarkerNavigationWidget.TitleMenu,title:NextMarkerAction.LABEL,icon:registerIcon("marker-navigation-next",Codicon.arrowDown,nls.localize("nextMarkerIcon","Icon for goto next marker.")),group:"navigation",order:1}})}}NextMarkerAction.ID="editor.action.marker.next",NextMarkerAction.LABEL=nls.localize("markerAction.next.label","Go to Next Problem (Error, Warning, Info)");class PrevMarkerAction extends MarkerNavigationAction{constructor(){super(!1,!1,{id:PrevMarkerAction.ID,label:PrevMarkerAction.LABEL,alias:"Go to Previous Problem (Error, Warning, Info)",precondition:void 0,kbOpts:{kbExpr:EditorContextKeys.focus,primary:1602,weight:100},menuOpts:{menuId:MarkerNavigationWidget.TitleMenu,title:NextMarkerAction.LABEL,icon:registerIcon("marker-navigation-previous",Codicon.arrowUp,nls.localize("previousMarkerIcon","Icon for goto previous marker.")),group:"navigation",order:2}})}}PrevMarkerAction.ID="editor.action.marker.prev",PrevMarkerAction.LABEL=nls.localize("markerAction.previous.label","Go to Previous Problem (Error, Warning, Info)");class NextMarkerInFilesAction extends MarkerNavigationAction{constructor(){super(!0,!0,{id:"editor.action.marker.nextInFiles",label:nls.localize("markerAction.nextInFiles.label","Go to Next Problem in Files (Error, Warning, Info)"),alias:"Go to Next Problem in Files (Error, Warning, Info)",precondition:void 0,kbOpts:{kbExpr:EditorContextKeys.focus,primary:66,weight:100},menuOpts:{menuId:MenuId.MenubarGoMenu,title:nls.localize({key:"miGotoNextProblem",comment:["&& denotes a mnemonic"]},"Next &&Problem"),group:"6_problem_nav",order:1}})}}class PrevMarkerInFilesAction extends MarkerNavigationAction{constructor(){super(!1,!0,{id:"editor.action.marker.prevInFiles",label:nls.localize("markerAction.previousInFiles.label","Go to Previous Problem in Files (Error, Warning, Info)"),alias:"Go to Previous Problem in Files (Error, Warning, Info)",precondition:void 0,kbOpts:{kbExpr:EditorContextKeys.focus,primary:1090,weight:100},menuOpts:{menuId:MenuId.MenubarGoMenu,title:nls.localize({key:"miGotoPreviousProblem",comment:["&& denotes a mnemonic"]},"Previous &&Problem"),group:"6_problem_nav",order:2}})}}registerEditorContribution(MarkerController.ID,MarkerController),registerEditorAction(NextMarkerAction),registerEditorAction(PrevMarkerAction),registerEditorAction(NextMarkerInFilesAction),registerEditorAction(PrevMarkerInFilesAction);const CONTEXT_MARKERS_NAVIGATION_VISIBLE=new RawContextKey("markersNavigationVisible",!1),MarkerCommand=EditorCommand.bindToContribution(MarkerController.get);registerEditorCommand(new MarkerCommand({id:"closeMarkersNavigation",precondition:CONTEXT_MARKERS_NAVIGATION_VISIBLE,handler:e=>e.close(),kbOpts:{weight:150,kbExpr:EditorContextKeys.focus,primary:9,secondary:[1033]}}));