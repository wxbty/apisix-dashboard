var _a;import{globals}from"../common/platform.js";import{logOnceWebWorkerWarning}from"../common/worker/simpleWorker.js";const ttPolicy=null===(_a=window.trustedTypes)||void 0===_a?void 0:_a.createPolicy("defaultWorkerFactory",{createScriptURL:r=>r});function getWorker(r){if(globals.MonacoEnvironment){if("function"===typeof globals.MonacoEnvironment.getWorker)return globals.MonacoEnvironment.getWorker("workerMain.js",r);if("function"===typeof globals.MonacoEnvironment.getWorkerUrl){const e=globals.MonacoEnvironment.getWorkerUrl("workerMain.js",r);return new Worker(ttPolicy?ttPolicy.createScriptURL(e):e,{name:r})}}throw new Error("You must define a function MonacoEnvironment.getWorkerUrl or MonacoEnvironment.getWorker")}function isPromiseLike(r){return"function"===typeof r.then}class WebWorker{constructor(r,e,o,t,n){this.id=e;const i=getWorker(o);isPromiseLike(i)?this.worker=i:this.worker=Promise.resolve(i),this.postMessage(r,[]),this.worker.then((r=>{r.onmessage=function(r){t(r.data)},r.onmessageerror=n,"function"===typeof r.addEventListener&&r.addEventListener("error",n)}))}getId(){return this.id}postMessage(r,e){this.worker&&this.worker.then((o=>o.postMessage(r,e)))}dispose(){this.worker&&this.worker.then((r=>r.terminate())),this.worker=null}}export class DefaultWorkerFactory{constructor(r){this._label=r,this._webWorkerFailedBeforeError=!1}create(r,e,o){let t=++DefaultWorkerFactory.LAST_WORKER_ID;if(this._webWorkerFailedBeforeError)throw this._webWorkerFailedBeforeError;return new WebWorker(r,t,this._label||"anonymous"+t,e,(r=>{logOnceWebWorkerWarning(r),this._webWorkerFailedBeforeError=r,o(r)}))}}DefaultWorkerFactory.LAST_WORKER_ID=0;