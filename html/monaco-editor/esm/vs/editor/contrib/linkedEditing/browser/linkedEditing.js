var __decorate=this&&this.__decorate||function(e,t,i,n){var r,o=arguments.length,s=o<3?t:null===n?n=Object.getOwnPropertyDescriptor(t,i):n;if("object"===typeof Reflect&&"function"===typeof Reflect.decorate)s=Reflect.decorate(e,t,i,n);else for(var a=e.length-1;a>=0;a--)(r=e[a])&&(s=(o<3?r(s):o>3?r(t,i,s):r(t,i))||s);return o>3&&s&&Object.defineProperty(t,i,s),s},__param=this&&this.__param||function(e,t){return function(i,n){t(i,n,e)}},__awaiter=this&&this.__awaiter||function(e,t,i,n){function r(e){return e instanceof i?e:new i((function(t){t(e)}))}return new(i||(i=Promise))((function(i,o){function s(e){try{d(n.next(e))}catch(t){o(t)}}function a(e){try{d(n["throw"](e))}catch(t){o(t)}}function d(e){e.done?i(e.value):r(e.value).then(s,a)}d((n=n.apply(e,t||[])).next())}))};import*as arrays from"../../../../base/common/arrays.js";import{createCancelablePromise,Delayer,first}from"../../../../base/common/async.js";import{CancellationToken}from"../../../../base/common/cancellation.js";import{Color}from"../../../../base/common/color.js";import{isCancellationError,onUnexpectedError,onUnexpectedExternalError}from"../../../../base/common/errors.js";import{Event}from"../../../../base/common/event.js";import{Disposable,DisposableStore}from"../../../../base/common/lifecycle.js";import*as strings from"../../../../base/common/strings.js";import{URI}from"../../../../base/common/uri.js";import{EditorAction,EditorCommand,registerEditorAction,registerEditorCommand,registerEditorContribution,registerModelAndPositionCommand}from"../../../browser/editorExtensions.js";import{ICodeEditorService}from"../../../browser/services/codeEditorService.js";import{Position}from"../../../common/core/position.js";import{Range}from"../../../common/core/range.js";import{EditorContextKeys}from"../../../common/editorContextKeys.js";import{ModelDecorationOptions}from"../../../common/model/textModel.js";import{LinkedEditingRangeProviderRegistry}from"../../../common/languages.js";import{ILanguageConfigurationService}from"../../../common/languages/languageConfigurationRegistry.js";import*as nls from"../../../../nls.js";import{ContextKeyExpr,IContextKeyService,RawContextKey}from"../../../../platform/contextkey/common/contextkey.js";import{registerColor}from"../../../../platform/theme/common/colorRegistry.js";import{registerThemingParticipant}from"../../../../platform/theme/common/themeService.js";export const CONTEXT_ONTYPE_RENAME_INPUT_VISIBLE=new RawContextKey("LinkedEditingInputVisible",!1);const DECORATION_CLASS_NAME="linked-editing-decoration";let LinkedEditingContribution=class e extends Disposable{constructor(e,t,i){super(),this.languageConfigurationService=i,this._debounceDuration=200,this._localToDispose=this._register(new DisposableStore),this._editor=e,this._enabled=!1,this._visibleContextKey=CONTEXT_ONTYPE_RENAME_INPUT_VISIBLE.bindTo(t),this._currentDecorations=[],this._languageWordPattern=null,this._currentWordPattern=null,this._ignoreChangeEvent=!1,this._localToDispose=this._register(new DisposableStore),this._rangeUpdateTriggerPromise=null,this._rangeSyncTriggerPromise=null,this._currentRequest=null,this._currentRequestPosition=null,this._currentRequestModelVersion=null,this._register(this._editor.onDidChangeModel((()=>this.reinitialize(!0)))),this._register(this._editor.onDidChangeConfiguration((e=>{(e.hasChanged(62)||e.hasChanged(82))&&this.reinitialize(!1)}))),this._register(LinkedEditingRangeProviderRegistry.onDidChange((()=>this.reinitialize(!1)))),this._register(this._editor.onDidChangeModelLanguage((()=>this.reinitialize(!0)))),this.reinitialize(!0)}static get(t){return t.getContribution(e.ID)}reinitialize(e){const t=this._editor.getModel(),i=null!==t&&(this._editor.getOption(62)||this._editor.getOption(82))&&LinkedEditingRangeProviderRegistry.has(t);if(i===this._enabled&&!e)return;if(this._enabled=i,this.clearRanges(),this._localToDispose.clear(),!i||null===t)return;this._localToDispose.add(Event.runAndSubscribe(t.onDidChangeLanguageConfiguration,(()=>{this._languageWordPattern=this.languageConfigurationService.getLanguageConfiguration(t.getLanguageId()).getWordDefinition()})));const n=new Delayer(this._debounceDuration),r=()=>{this._rangeUpdateTriggerPromise=n.trigger((()=>this.updateRanges()),this._debounceDuration)},o=new Delayer(0),s=e=>{this._rangeSyncTriggerPromise=o.trigger((()=>this._syncRanges(e)))};this._localToDispose.add(this._editor.onDidChangeCursorPosition((()=>{r()}))),this._localToDispose.add(this._editor.onDidChangeModelContent((e=>{if(!this._ignoreChangeEvent&&this._currentDecorations.length>0){const i=t.getDecorationRange(this._currentDecorations[0]);if(i&&e.changes.every((e=>i.intersectRanges(e.range))))return void s(this._currentDecorations)}r()}))),this._localToDispose.add({dispose:()=>{n.cancel(),o.cancel()}}),this.updateRanges()}_syncRanges(e){if(!this._editor.hasModel()||e!==this._currentDecorations||0===e.length)return;const t=this._editor.getModel(),i=t.getDecorationRange(e[0]);if(!i||i.startLineNumber!==i.endLineNumber)return this.clearRanges();const n=t.getValueInRange(i);if(this._currentWordPattern){const e=n.match(this._currentWordPattern),t=e?e[0].length:0;if(t!==n.length)return this.clearRanges()}let r=[];for(let o=1,s=e.length;o<s;o++){const i=t.getDecorationRange(e[o]);if(i)if(i.startLineNumber!==i.endLineNumber)r.push({range:i,text:n});else{let e=t.getValueInRange(i),o=n,s=i.startColumn,a=i.endColumn;const d=strings.commonPrefixLength(e,o);s+=d,e=e.substr(d),o=o.substr(d);const c=strings.commonSuffixLength(e,o);a-=c,e=e.substr(0,e.length-c),o=o.substr(0,o.length-c),s===a&&0===o.length||r.push({range:new Range(i.startLineNumber,s,i.endLineNumber,a),text:o})}}if(0!==r.length)try{this._editor.popUndoStop(),this._ignoreChangeEvent=!0;const e=this._editor._getViewModel().getPrevEditOperationType();this._editor.executeEdits("linkedEditing",r),this._editor._getViewModel().setPrevEditOperationType(e)}finally{this._ignoreChangeEvent=!1}}dispose(){this.clearRanges(),super.dispose()}clearRanges(){this._visibleContextKey.set(!1),this._currentDecorations=this._editor.deltaDecorations(this._currentDecorations,[]),this._currentRequest&&(this._currentRequest.cancel(),this._currentRequest=null,this._currentRequestPosition=null)}updateRanges(t=!1){return __awaiter(this,void 0,void 0,(function*(){if(!this._editor.hasModel())return void this.clearRanges();const i=this._editor.getPosition();if(!this._enabled&&!t||this._editor.getSelections().length>1)return void this.clearRanges();const n=this._editor.getModel(),r=n.getVersionId();if(this._currentRequestPosition&&this._currentRequestModelVersion===r){if(i.equals(this._currentRequestPosition))return;if(this._currentDecorations&&this._currentDecorations.length>0){const e=n.getDecorationRange(this._currentDecorations[0]);if(e&&e.containsPosition(i))return}}this._currentRequestPosition=i,this._currentRequestModelVersion=r;const o=createCancelablePromise((t=>__awaiter(this,void 0,void 0,(function*(){try{const s=yield getLinkedEditingRanges(n,i,t);if(o!==this._currentRequest)return;if(this._currentRequest=null,r!==n.getVersionId())return;let a=[];(null===s||void 0===s?void 0:s.ranges)&&(a=s.ranges),this._currentWordPattern=(null===s||void 0===s?void 0:s.wordPattern)||this._languageWordPattern;let d=!1;for(let e=0,t=a.length;e<t;e++)if(Range.containsPosition(a[e],i)){if(d=!0,0!==e){const t=a[e];a.splice(e,1),a.unshift(t)}break}if(!d)return void this.clearRanges();const c=a.map((t=>({range:t,options:e.DECORATION})));this._visibleContextKey.set(!0),this._currentDecorations=this._editor.deltaDecorations(this._currentDecorations,c)}catch(s){isCancellationError(s)||onUnexpectedError(s),this._currentRequest!==o&&this._currentRequest||this.clearRanges()}}))));return this._currentRequest=o,o}))}};LinkedEditingContribution.ID="editor.contrib.linkedEditing",LinkedEditingContribution.DECORATION=ModelDecorationOptions.register({description:"linked-editing",stickiness:0,className:DECORATION_CLASS_NAME}),LinkedEditingContribution=__decorate([__param(1,IContextKeyService),__param(2,ILanguageConfigurationService)],LinkedEditingContribution);export{LinkedEditingContribution};export class LinkedEditingAction extends EditorAction{constructor(){super({id:"editor.action.linkedEditing",label:nls.localize("linkedEditing.label","Start Linked Editing"),alias:"Start Linked Editing",precondition:ContextKeyExpr.and(EditorContextKeys.writable,EditorContextKeys.hasRenameProvider),kbOpts:{kbExpr:EditorContextKeys.editorTextFocus,primary:3132,weight:100}})}runCommand(e,t){const i=e.get(ICodeEditorService),[n,r]=Array.isArray(t)&&t||[void 0,void 0];return URI.isUri(n)&&Position.isIPosition(r)?i.openCodeEditor({resource:n},i.getActiveCodeEditor()).then((e=>{e&&(e.setPosition(r),e.invokeWithinContext((t=>(this.reportTelemetry(t,e),this.run(t,e)))))}),onUnexpectedError):super.runCommand(e,t)}run(e,t){const i=LinkedEditingContribution.get(t);return i?Promise.resolve(i.updateRanges(!0)):Promise.resolve()}}const LinkedEditingCommand=EditorCommand.bindToContribution(LinkedEditingContribution.get);function getLinkedEditingRanges(e,t,i){const n=LinkedEditingRangeProviderRegistry.ordered(e);return first(n.map((n=>()=>__awaiter(this,void 0,void 0,(function*(){try{return yield n.provideLinkedEditingRanges(e,t,i)}catch(r){return void onUnexpectedExternalError(r)}})))),(e=>!!e&&arrays.isNonEmptyArray(null===e||void 0===e?void 0:e.ranges)))}registerEditorCommand(new LinkedEditingCommand({id:"cancelLinkedEditingInput",precondition:CONTEXT_ONTYPE_RENAME_INPUT_VISIBLE,handler:e=>e.clearRanges(),kbOpts:{kbExpr:EditorContextKeys.editorTextFocus,weight:199,primary:9,secondary:[1033]}}));export const editorLinkedEditingBackground=registerColor("editor.linkedEditingBackground",{dark:Color.fromHex("#f00").transparent(.3),light:Color.fromHex("#f00").transparent(.3),hc:Color.fromHex("#f00").transparent(.3)},nls.localize("editorLinkedEditingBackground","Background color when the editor auto renames on type."));registerThemingParticipant(((e,t)=>{const i=e.getColor(editorLinkedEditingBackground);i&&t.addRule(`.monaco-editor .${DECORATION_CLASS_NAME} { background: ${i}; border-left-color: ${i}; }`)})),registerModelAndPositionCommand("_executeLinkedEditingProvider",((e,t)=>getLinkedEditingRanges(e,t,CancellationToken.None))),registerEditorContribution(LinkedEditingContribution.ID,LinkedEditingContribution),registerEditorAction(LinkedEditingAction);