import{show}from"../../dom.js";import{RunOnceScheduler}from"../../../common/async.js";import{Color}from"../../../common/color.js";import{Disposable}from"../../../common/lifecycle.js";import{mixin}from"../../../common/objects.js";import"./progressbar.css";const CSS_DONE="done",CSS_ACTIVE="active",CSS_INFINITE="infinite",CSS_INFINITE_LONG_RUNNING="infinite-long-running",CSS_DISCRETE="discrete",defaultOpts={progressBarBackground:Color.fromHex("#0E70C0")};export class ProgressBar extends Disposable{constructor(t,e){super(),this.options=e||Object.create(null),mixin(this.options,defaultOpts,!1),this.workedVal=0,this.progressBarBackground=this.options.progressBarBackground,this.showDelayedScheduler=this._register(new RunOnceScheduler((()=>show(this.element)),0)),this.longRunningScheduler=this._register(new RunOnceScheduler((()=>this.infiniteLongRunning()),ProgressBar.LONG_RUNNING_INFINITE_THRESHOLD)),this.create(t)}create(t){this.element=document.createElement("div"),this.element.classList.add("monaco-progress-container"),this.element.setAttribute("role","progressbar"),this.element.setAttribute("aria-valuemin","0"),t.appendChild(this.element),this.bit=document.createElement("div"),this.bit.classList.add("progress-bit"),this.element.appendChild(this.bit),this.applyStyles()}off(){this.bit.style.width="inherit",this.bit.style.opacity="1",this.element.classList.remove(CSS_ACTIVE,CSS_INFINITE,CSS_INFINITE_LONG_RUNNING,CSS_DISCRETE),this.workedVal=0,this.totalWork=void 0,this.longRunningScheduler.cancel()}stop(){return this.doDone(!1)}doDone(t){return this.element.classList.add(CSS_DONE),this.element.classList.contains(CSS_INFINITE)?(this.bit.style.opacity="0",t?setTimeout((()=>this.off()),200):this.off()):(this.bit.style.width="inherit",t?setTimeout((()=>this.off()),200):this.off()),this}infinite(){return this.bit.style.width="2%",this.bit.style.opacity="1",this.element.classList.remove(CSS_DISCRETE,CSS_DONE,CSS_INFINITE_LONG_RUNNING),this.element.classList.add(CSS_ACTIVE,CSS_INFINITE),this.longRunningScheduler.schedule(),this}infiniteLongRunning(){this.element.classList.add(CSS_INFINITE_LONG_RUNNING)}getContainer(){return this.element}style(t){this.progressBarBackground=t.progressBarBackground,this.applyStyles()}applyStyles(){if(this.bit){const t=this.progressBarBackground?this.progressBarBackground.toString():"";this.bit.style.backgroundColor=t}}}ProgressBar.LONG_RUNNING_INFINITE_THRESHOLD=1e4;