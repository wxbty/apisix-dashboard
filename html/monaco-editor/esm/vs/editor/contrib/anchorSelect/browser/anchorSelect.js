var __decorate=this&&this.__decorate||function(o,e,t,n){var r,i=arguments.length,c=i<3?e:null===n?n=Object.getOwnPropertyDescriptor(e,t):n;if("object"===typeof Reflect&&"function"===typeof Reflect.decorate)c=Reflect.decorate(o,e,t,n);else for(var s=o.length-1;s>=0;s--)(r=o[s])&&(c=(i<3?r(c):i>3?r(e,t,c):r(e,t))||c);return i>3&&c&&Object.defineProperty(e,t,c),c},__param=this&&this.__param||function(o,e){return function(t,n){e(t,n,o)}},__awaiter=this&&this.__awaiter||function(o,e,t,n){function r(o){return o instanceof t?o:new t((function(e){e(o)}))}return new(t||(t=Promise))((function(t,i){function c(o){try{l(n.next(o))}catch(e){i(e)}}function s(o){try{l(n["throw"](o))}catch(e){i(e)}}function l(o){o.done?t(o.value):r(o.value).then(c,s)}l((n=n.apply(o,e||[])).next())}))};import{alert}from"../../../../base/browser/ui/aria/aria.js";import{MarkdownString}from"../../../../base/common/htmlContent.js";import{KeyChord}from"../../../../base/common/keyCodes.js";import"./anchorSelect.css";import{EditorAction,registerEditorAction,registerEditorContribution}from"../../../browser/editorExtensions.js";import{Selection}from"../../../common/core/selection.js";import{EditorContextKeys}from"../../../common/editorContextKeys.js";import{localize}from"../../../../nls.js";import{IContextKeyService,RawContextKey}from"../../../../platform/contextkey/common/contextkey.js";export const SelectionAnchorSet=new RawContextKey("selectionAnchorSet",!1);let SelectionAnchorController=class o{constructor(o,e){this.editor=o,this.selectionAnchorSetContextKey=SelectionAnchorSet.bindTo(e),this.modelChangeListener=o.onDidChangeModel((()=>this.selectionAnchorSetContextKey.reset()))}static get(e){return e.getContribution(o.ID)}setSelectionAnchor(){if(this.editor.hasModel()){const o=this.editor.getPosition(),e=this.decorationId?[this.decorationId]:[],t=this.editor.deltaDecorations(e,[{range:Selection.fromPositions(o,o),options:{description:"selection-anchor",stickiness:1,hoverMessage:(new MarkdownString).appendText(localize("selectionAnchor","Selection Anchor")),className:"selection-anchor"}}]);this.decorationId=t[0],this.selectionAnchorSetContextKey.set(!!this.decorationId),alert(localize("anchorSet","Anchor set at {0}:{1}",o.lineNumber,o.column))}}goToSelectionAnchor(){if(this.editor.hasModel()&&this.decorationId){const o=this.editor.getModel().getDecorationRange(this.decorationId);o&&this.editor.setPosition(o.getStartPosition())}}selectFromAnchorToCursor(){if(this.editor.hasModel()&&this.decorationId){const o=this.editor.getModel().getDecorationRange(this.decorationId);if(o){const e=this.editor.getPosition();this.editor.setSelection(Selection.fromPositions(o.getStartPosition(),e)),this.cancelSelectionAnchor()}}}cancelSelectionAnchor(){this.decorationId&&(this.editor.deltaDecorations([this.decorationId],[]),this.decorationId=void 0,this.selectionAnchorSetContextKey.set(!1))}dispose(){this.cancelSelectionAnchor(),this.modelChangeListener.dispose()}};SelectionAnchorController.ID="editor.contrib.selectionAnchorController",SelectionAnchorController=__decorate([__param(1,IContextKeyService)],SelectionAnchorController);class SetSelectionAnchor extends EditorAction{constructor(){super({id:"editor.action.setSelectionAnchor",label:localize("setSelectionAnchor","Set Selection Anchor"),alias:"Set Selection Anchor",precondition:void 0,kbOpts:{kbExpr:EditorContextKeys.editorTextFocus,primary:KeyChord(2089,2080),weight:100}})}run(o,e){var t;return __awaiter(this,void 0,void 0,(function*(){null===(t=SelectionAnchorController.get(e))||void 0===t||t.setSelectionAnchor()}))}}class GoToSelectionAnchor extends EditorAction{constructor(){super({id:"editor.action.goToSelectionAnchor",label:localize("goToSelectionAnchor","Go to Selection Anchor"),alias:"Go to Selection Anchor",precondition:SelectionAnchorSet})}run(o,e){var t;return __awaiter(this,void 0,void 0,(function*(){null===(t=SelectionAnchorController.get(e))||void 0===t||t.goToSelectionAnchor()}))}}class SelectFromAnchorToCursor extends EditorAction{constructor(){super({id:"editor.action.selectFromAnchorToCursor",label:localize("selectFromAnchorToCursor","Select from Anchor to Cursor"),alias:"Select from Anchor to Cursor",precondition:SelectionAnchorSet,kbOpts:{kbExpr:EditorContextKeys.editorTextFocus,primary:KeyChord(2089,2089),weight:100}})}run(o,e){var t;return __awaiter(this,void 0,void 0,(function*(){null===(t=SelectionAnchorController.get(e))||void 0===t||t.selectFromAnchorToCursor()}))}}class CancelSelectionAnchor extends EditorAction{constructor(){super({id:"editor.action.cancelSelectionAnchor",label:localize("cancelSelectionAnchor","Cancel Selection Anchor"),alias:"Cancel Selection Anchor",precondition:SelectionAnchorSet,kbOpts:{kbExpr:EditorContextKeys.editorTextFocus,primary:9,weight:100}})}run(o,e){var t;return __awaiter(this,void 0,void 0,(function*(){null===(t=SelectionAnchorController.get(e))||void 0===t||t.cancelSelectionAnchor()}))}}registerEditorContribution(SelectionAnchorController.ID,SelectionAnchorController),registerEditorAction(SetSelectionAnchor),registerEditorAction(GoToSelectionAnchor),registerEditorAction(SelectFromAnchorToCursor),registerEditorAction(CancelSelectionAnchor);