var StorageState,__awaiter=this&&this.__awaiter||function(e,t,i,s){function n(e){return e instanceof i?e:new i((function(t){t(e)}))}return new(i||(i=Promise))((function(i,r){function a(e){try{h(s.next(e))}catch(t){r(t)}}function o(e){try{h(s["throw"](e))}catch(t){r(t)}}function h(e){e.done?i(e.value):n(e.value).then(a,o)}h((s=s.apply(e,t||[])).next())}))};import{ThrottledDelayer}from"../../../common/async.js";import{Emitter,Event}from"../../../common/event.js";import{Disposable}from"../../../common/lifecycle.js";import{isUndefinedOrNull}from"../../../common/types.js";(function(e){e[e["None"]=0]="None",e[e["Initialized"]=1]="Initialized",e[e["Closed"]=2]="Closed"})(StorageState||(StorageState={}));export class Storage extends Disposable{constructor(e,t=Object.create(null)){super(),this.database=e,this.options=t,this._onDidChangeStorage=this._register(new Emitter),this.onDidChangeStorage=this._onDidChangeStorage.event,this.state=StorageState.None,this.cache=new Map,this.flushDelayer=new ThrottledDelayer(Storage.DEFAULT_FLUSH_DELAY),this.pendingDeletes=new Set,this.pendingInserts=new Map,this.whenFlushedCallbacks=[],this.registerListeners()}registerListeners(){this._register(this.database.onDidChangeItemsExternal((e=>this.onDidChangeItemsExternal(e))))}onDidChangeItemsExternal(e){var t,i;null===(t=e.changed)||void 0===t||t.forEach(((e,t)=>this.accept(t,e))),null===(i=e.deleted)||void 0===i||i.forEach((e=>this.accept(e,void 0)))}accept(e,t){if(this.state===StorageState.Closed)return;let i=!1;if(isUndefinedOrNull(t))i=this.cache.delete(e);else{const s=this.cache.get(e);s!==t&&(this.cache.set(e,t),i=!0)}i&&this._onDidChangeStorage.fire(e)}get(e,t){const i=this.cache.get(e);return isUndefinedOrNull(i)?t:i}getBoolean(e,t){const i=this.get(e);return isUndefinedOrNull(i)?t:"true"===i}getNumber(e,t){const i=this.get(e);return isUndefinedOrNull(i)?t:parseInt(i,10)}set(e,t){return __awaiter(this,void 0,void 0,(function*(){if(this.state===StorageState.Closed)return;if(isUndefinedOrNull(t))return this.delete(e);const i=String(t),s=this.cache.get(e);return s!==i?(this.cache.set(e,i),this.pendingInserts.set(e,i),this.pendingDeletes.delete(e),this._onDidChangeStorage.fire(e),this.doFlush()):void 0}))}delete(e){return __awaiter(this,void 0,void 0,(function*(){if(this.state===StorageState.Closed)return;const t=this.cache.delete(e);return t?(this.pendingDeletes.has(e)||this.pendingDeletes.add(e),this.pendingInserts.delete(e),this._onDidChangeStorage.fire(e),this.doFlush()):void 0}))}get hasPending(){return this.pendingInserts.size>0||this.pendingDeletes.size>0}flushPending(){return __awaiter(this,void 0,void 0,(function*(){if(!this.hasPending)return;const e={insert:this.pendingInserts,delete:this.pendingDeletes};return this.pendingDeletes=new Set,this.pendingInserts=new Map,this.database.updateItems(e).finally((()=>{var e;if(!this.hasPending)while(this.whenFlushedCallbacks.length)null===(e=this.whenFlushedCallbacks.pop())||void 0===e||e()}))}))}doFlush(e){return __awaiter(this,void 0,void 0,(function*(){return this.flushDelayer.trigger((()=>this.flushPending()),e)}))}dispose(){this.flushDelayer.dispose(),super.dispose()}}Storage.DEFAULT_FLUSH_DELAY=100;export class InMemoryStorageDatabase{constructor(){this.onDidChangeItemsExternal=Event.None,this.items=new Map}updateItems(e){return __awaiter(this,void 0,void 0,(function*(){e.insert&&e.insert.forEach(((e,t)=>this.items.set(t,e))),e.delete&&e.delete.forEach((e=>this.items.delete(e)))}))}}