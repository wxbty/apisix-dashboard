var __decorate=this&&this.__decorate||function(e,r,t,i){var s,o=arguments.length,n=o<3?r:null===i?i=Object.getOwnPropertyDescriptor(r,t):i;if("object"===typeof Reflect&&"function"===typeof Reflect.decorate)n=Reflect.decorate(e,r,t,i);else for(var a=e.length-1;a>=0;a--)(s=e[a])&&(n=(o<3?s(n):o>3?s(r,t,n):s(r,t))||n);return o>3&&n&&Object.defineProperty(r,t,n),n},__param=this&&this.__param||function(e,r){return function(t,i){r(t,i,e)}};import{binarySearch}from"../../../../base/common/arrays.js";import{Emitter}from"../../../../base/common/event.js";import{DisposableStore}from"../../../../base/common/lifecycle.js";import{LinkedList}from"../../../../base/common/linkedList.js";import{compare}from"../../../../base/common/strings.js";import{URI}from"../../../../base/common/uri.js";import{Range}from"../../../common/core/range.js";import{registerSingleton}from"../../../../platform/instantiation/common/extensions.js";import{createDecorator}from"../../../../platform/instantiation/common/instantiation.js";import{IMarkerService,MarkerSeverity}from"../../../../platform/markers/common/markers.js";import{IConfigurationService}from"../../../../platform/configuration/common/configuration.js";export class MarkerCoordinate{constructor(e,r,t){this.marker=e,this.index=r,this.total=t}}let MarkerList=class{constructor(e,r,t){this._markerService=r,this._configService=t,this._onDidChange=new Emitter,this.onDidChange=this._onDidChange.event,this._dispoables=new DisposableStore,this._markers=[],this._nextIdx=-1,URI.isUri(e)?this._resourceFilter=r=>r.toString()===e.toString():e&&(this._resourceFilter=e);const i=this._configService.getValue("problems.sortOrder"),s=(e,r)=>{let t=compare(e.resource.toString(),r.resource.toString());return t="position"===i?Range.compareRangesUsingStarts(e,r)||MarkerSeverity.compare(e.severity,r.severity):MarkerSeverity.compare(e.severity,r.severity)||Range.compareRangesUsingStarts(e,r),t},o=()=>{this._markers=this._markerService.read({resource:URI.isUri(e)?e:void 0,severities:MarkerSeverity.Error|MarkerSeverity.Warning|MarkerSeverity.Info}),"function"===typeof e&&(this._markers=this._markers.filter((e=>this._resourceFilter(e.resource)))),this._markers.sort(s)};o(),this._dispoables.add(r.onMarkerChanged((e=>{this._resourceFilter&&!e.some((e=>this._resourceFilter(e)))||(o(),this._nextIdx=-1,this._onDidChange.fire())})))}dispose(){this._dispoables.dispose(),this._onDidChange.dispose()}matches(e){return!this._resourceFilter&&!e||!(!this._resourceFilter||!e)&&this._resourceFilter(e)}get selected(){const e=this._markers[this._nextIdx];return e&&new MarkerCoordinate(e,this._nextIdx+1,this._markers.length)}_initIdx(e,r,t){let i=!1,s=this._markers.findIndex((r=>r.resource.toString()===e.uri.toString()));s<0&&(s=binarySearch(this._markers,{resource:e.uri},((e,r)=>compare(e.resource.toString(),r.resource.toString()))),s<0&&(s=~s));for(let o=s;o<this._markers.length;o++){let t=Range.lift(this._markers[o]);if(t.isEmpty()){const r=e.getWordAtPosition(t.getStartPosition());r&&(t=new Range(t.startLineNumber,r.startColumn,t.startLineNumber,r.endColumn))}if(r&&(t.containsPosition(r)||r.isBeforeOrEqual(t.getStartPosition()))){this._nextIdx=o,i=!0;break}if(this._markers[o].resource.toString()!==e.uri.toString())break}i||(this._nextIdx=t?0:this._markers.length-1),this._nextIdx<0&&(this._nextIdx=this._markers.length-1)}resetIndex(){this._nextIdx=-1}move(e,r,t){if(0===this._markers.length)return!1;let i=this._nextIdx;return-1===this._nextIdx?this._initIdx(r,t,e):e?this._nextIdx=(this._nextIdx+1)%this._markers.length:e||(this._nextIdx=(this._nextIdx-1+this._markers.length)%this._markers.length),i!==this._nextIdx}find(e,r){let t=this._markers.findIndex((r=>r.resource.toString()===e.toString()));if(!(t<0))for(;t<this._markers.length;t++)if(Range.containsPosition(this._markers[t],r))return new MarkerCoordinate(this._markers[t],t+1,this._markers.length)}};MarkerList=__decorate([__param(1,IMarkerService),__param(2,IConfigurationService)],MarkerList);export{MarkerList};export const IMarkerNavigationService=createDecorator("IMarkerNavigationService");let MarkerNavigationService=class{constructor(e,r){this._markerService=e,this._configService=r,this._provider=new LinkedList}getMarkerList(e){for(let r of this._provider){const t=r.getMarkerList(e);if(t)return t}return new MarkerList(e,this._markerService,this._configService)}};MarkerNavigationService=__decorate([__param(0,IMarkerService),__param(1,IConfigurationService)],MarkerNavigationService),registerSingleton(IMarkerNavigationService,MarkerNavigationService,!0);