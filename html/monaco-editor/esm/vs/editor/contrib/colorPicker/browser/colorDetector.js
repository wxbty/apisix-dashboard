var __decorate=this&&this.__decorate||function(o,e,t,r){var i,s=arguments.length,n=s<3?e:null===r?r=Object.getOwnPropertyDescriptor(e,t):r;if("object"===typeof Reflect&&"function"===typeof Reflect.decorate)n=Reflect.decorate(o,e,t,r);else for(var a=o.length-1;a>=0;a--)(i=o[a])&&(n=(s<3?i(n):s>3?i(e,t,n):i(e,t))||n);return s>3&&n&&Object.defineProperty(e,t,n),n},__param=this&&this.__param||function(o,e){return function(t,r){e(t,r,o)}};import{createCancelablePromise,TimeoutTimer}from"../../../../base/common/async.js";import{RGBA}from"../../../../base/common/color.js";import{onUnexpectedError}from"../../../../base/common/errors.js";import{Disposable,DisposableStore}from"../../../../base/common/lifecycle.js";import{noBreakWhitespace}from"../../../../base/common/strings.js";import{DynamicCssRules}from"../../../browser/editorDom.js";import{registerEditorContribution}from"../../../browser/editorExtensions.js";import{Range}from"../../../common/core/range.js";import{ModelDecorationOptions}from"../../../common/model/textModel.js";import{ColorProviderRegistry}from"../../../common/languages.js";import{getColors}from"./color.js";import{IConfigurationService}from"../../../../platform/configuration/common/configuration.js";export const ColorDecorationInjectedTextMarker=Object.create({});const MAX_DECORATORS=500;let ColorDetector=class o extends Disposable{constructor(o,e){super(),this._editor=o,this._configurationService=e,this._localToDispose=this._register(new DisposableStore),this._decorationsIds=[],this._colorDatas=new Map,this._colorDecoratorIds=new Set,this._ruleFactory=new DynamicCssRules(this._editor),this._colorDecorationClassRefs=this._register(new DisposableStore),this._register(o.onDidChangeModel((()=>{this._isEnabled=this.isEnabled(),this.onModelChanged()}))),this._register(o.onDidChangeModelLanguage((()=>this.onModelChanged()))),this._register(ColorProviderRegistry.onDidChange((()=>this.onModelChanged()))),this._register(o.onDidChangeConfiguration((()=>{let o=this._isEnabled;this._isEnabled=this.isEnabled(),o!==this._isEnabled&&(this._isEnabled?this.onModelChanged():this.removeAllDecorations())}))),this._timeoutTimer=null,this._computePromise=null,this._isEnabled=this.isEnabled(),this.onModelChanged()}isEnabled(){const o=this._editor.getModel();if(!o)return!1;const e=o.getLanguageId(),t=this._configurationService.getValue(e);if(t&&"object"===typeof t){const o=t["colorDecorators"];if(o&&void 0!==o["enable"]&&!o["enable"])return o["enable"]}return this._editor.getOption(17)}static get(o){return o.getContribution(this.ID)}dispose(){this.stop(),this.removeAllDecorations(),super.dispose()}onModelChanged(){if(this.stop(),!this._isEnabled)return;const e=this._editor.getModel();e&&ColorProviderRegistry.has(e)&&(this._localToDispose.add(this._editor.onDidChangeModelContent((()=>{this._timeoutTimer||(this._timeoutTimer=new TimeoutTimer,this._timeoutTimer.cancelAndSet((()=>{this._timeoutTimer=null,this.beginCompute()}),o.RECOMPUTE_TIME))}))),this.beginCompute())}beginCompute(){this._computePromise=createCancelablePromise((o=>{const e=this._editor.getModel();return e?getColors(e,o):Promise.resolve([])})),this._computePromise.then((o=>{this.updateDecorations(o),this.updateColorDecorators(o),this._computePromise=null}),onUnexpectedError)}stop(){this._timeoutTimer&&(this._timeoutTimer.cancel(),this._timeoutTimer=null),this._computePromise&&(this._computePromise.cancel(),this._computePromise=null),this._localToDispose.clear()}updateDecorations(o){const e=o.map((o=>({range:{startLineNumber:o.colorInfo.range.startLineNumber,startColumn:o.colorInfo.range.startColumn,endLineNumber:o.colorInfo.range.endLineNumber,endColumn:o.colorInfo.range.endColumn},options:ModelDecorationOptions.EMPTY})));this._decorationsIds=this._editor.deltaDecorations(this._decorationsIds,e),this._colorDatas=new Map,this._decorationsIds.forEach(((e,t)=>this._colorDatas.set(e,o[t])))}updateColorDecorators(o){this._colorDecorationClassRefs.clear();let e=[];for(let t=0;t<o.length&&e.length<MAX_DECORATORS;t++){const{red:r,green:i,blue:s,alpha:n}=o[t].colorInfo.color,a=new RGBA(Math.round(255*r),Math.round(255*i),Math.round(255*s),n);let l=`rgba(${a.r}, ${a.g}, ${a.b}, ${a.a})`;const c=this._colorDecorationClassRefs.add(this._ruleFactory.createClassNameRef({backgroundColor:l}));e.push({range:{startLineNumber:o[t].colorInfo.range.startLineNumber,startColumn:o[t].colorInfo.range.startColumn,endLineNumber:o[t].colorInfo.range.endLineNumber,endColumn:o[t].colorInfo.range.endColumn},options:{description:"colorDetector",before:{content:noBreakWhitespace,inlineClassName:`${c.className} colorpicker-color-decoration`,inlineClassNameAffectsLetterSpacing:!0,attachedData:ColorDecorationInjectedTextMarker}}})}this._colorDecoratorIds=new Set(this._editor.deltaDecorations([...this._colorDecoratorIds],e))}removeAllDecorations(){this._decorationsIds=this._editor.deltaDecorations(this._decorationsIds,[]),this._colorDecoratorIds=new Set(this._editor.deltaDecorations([...this._colorDecoratorIds],[])),this._colorDecorationClassRefs.clear()}getColorData(o){const e=this._editor.getModel();if(!e)return null;const t=e.getDecorationsInRange(Range.fromPositions(o,o)).filter((o=>this._colorDatas.has(o.id)));return 0===t.length?null:this._colorDatas.get(t[0].id)}isColorDecorationId(o){return this._colorDecoratorIds.has(o)}};ColorDetector.ID="editor.contrib.colorDetector",ColorDetector.RECOMPUTE_TIME=1e3,ColorDetector=__decorate([__param(1,IConfigurationService)],ColorDetector);export{ColorDetector};registerEditorContribution(ColorDetector.ID,ColorDetector);