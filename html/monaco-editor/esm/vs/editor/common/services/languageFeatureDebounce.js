var IdentityHash,__decorate=this&&this.__decorate||function(e,t,a,o){var r,i=arguments.length,n=i<3?t:null===o?o=Object.getOwnPropertyDescriptor(t,a):o;if("object"===typeof Reflect&&"function"===typeof Reflect.decorate)n=Reflect.decorate(e,t,a,o);else for(var s=e.length-1;s>=0;s--)(r=e[s])&&(n=(i<3?r(n):i>3?r(t,a,n):r(t,a))||n);return i>3&&n&&Object.defineProperty(t,a,n),n},__param=this&&this.__param||function(e,t){return function(a,o){t(a,o,e)}};import{doHash}from"../../../base/common/hash.js";import{LRUCache}from"../../../base/common/map.js";import{clamp,MovingAverage,SlidingWindowAverage}from"../../../base/common/numbers.js";import{registerSingleton}from"../../../platform/instantiation/common/extensions.js";import{createDecorator}from"../../../platform/instantiation/common/instantiation.js";import{ILogService}from"../../../platform/log/common/log.js";export const ILanguageFeatureDebounceService=createDecorator("ILanguageFeatureDebounceService");(function(e){const t=new WeakMap;let a=0;function o(e){let o=t.get(e);return void 0===o&&(o=++a,t.set(e,o)),o}e.of=o})(IdentityHash||(IdentityHash={}));class FeatureDebounceInformation{constructor(e,t,a,o,r,i){this._logService=e,this._name=t,this._registry=a,this._default=o,this._min=r,this._max=i,this._cache=new LRUCache(50,.7)}_key(e){return e.id+this._registry.all(e).reduce(((e,t)=>doHash(IdentityHash.of(t),e)),0)}get(e){const t=this._key(e),a=this._cache.get(t);return a?clamp(a.value,this._min,this._max):this.default()}update(e,t){const a=this._key(e);let o=this._cache.get(a);o||(o=new SlidingWindowAverage(6),this._cache.set(a,o));const r=clamp(o.update(t),this._min,this._max);return this._logService.trace(`[DEBOUNCE: ${this._name}] for ${e.uri.toString()} is ${r}ms`),r}_overall(){const e=new MovingAverage;for(const[,t]of this._cache)e.update(t.value);return e.value}default(){const e=0|this._overall()||this._default;return clamp(e,this._min,this._max)}}let LanguageFeatureDebounceService=class{constructor(e){this._logService=e,this._data=new Map}for(e,t,a){var o,r,i;const n=null!==(o=null===a||void 0===a?void 0:a.min)&&void 0!==o?o:50,s=null!==(r=null===a||void 0===a?void 0:a.max)&&void 0!==r?r:Math.pow(n,2),c=null!==(i=null===a||void 0===a?void 0:a.key)&&void 0!==i?i:void 0,u=`${IdentityHash.of(e)},${n}${c?","+c:""}`;let l=this._data.get(u);return l||(l=new FeatureDebounceInformation(this._logService,t,e,0|this._overallAverage()||1.5*n,n,s),this._data.set(u,l)),l}_overallAverage(){let e=new MovingAverage;for(let t of this._data.values())e.update(t.default());return e.value}};LanguageFeatureDebounceService=__decorate([__param(0,ILogService)],LanguageFeatureDebounceService);export{LanguageFeatureDebounceService};registerSingleton(ILanguageFeatureDebounceService,LanguageFeatureDebounceService,!0);