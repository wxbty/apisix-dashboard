import*as dom from"./dom.js";import{IframeUtils}from"./iframe.js";import{StandardMouseEvent}from"./mouseEvent.js";import{DisposableStore}from"../common/lifecycle.js";import{isIOS}from"../common/platform.js";export function standardMouseMoveMerger(o,t){let e=new StandardMouseEvent(t);return e.preventDefault(),{leftButton:e.leftButton,buttons:e.buttons,posx:e.posx,posy:e.posy}}export class GlobalMouseMoveMonitor{constructor(){this._hooks=new DisposableStore,this._mouseMoveEventMerger=null,this._mouseMoveCallback=null,this._onStopCallback=null}dispose(){this.stopMonitoring(!1),this._hooks.dispose()}stopMonitoring(o,t){if(!this.isMonitoring())return;this._hooks.clear(),this._mouseMoveEventMerger=null,this._mouseMoveCallback=null;const e=this._onStopCallback;this._onStopCallback=null,o&&e&&e(t)}isMonitoring(){return!!this._mouseMoveEventMerger}startMonitoring(o,t,e,s,i){if(this.isMonitoring())return;this._mouseMoveEventMerger=e,this._mouseMoveCallback=s,this._onStopCallback=i;const n=IframeUtils.getSameOriginWindowChain(),r=isIOS?"pointermove":"mousemove",a="mouseup",l=n.map((o=>o.window.document)),m=dom.getShadowRoot(o);m&&l.unshift(m);for(const d of l)this._hooks.add(dom.addDisposableThrottledListener(d,r,(o=>{o.buttons===t?this._mouseMoveCallback(o):this.stopMonitoring(!0)}),((o,t)=>this._mouseMoveEventMerger(o,t)))),this._hooks.add(dom.addDisposableListener(d,a,(o=>this.stopMonitoring(!0))));if(IframeUtils.hasDifferentOriginAncestor()){let o=n[n.length-1];this._hooks.add(dom.addDisposableListener(o.window.document,"mouseout",(o=>{let t=new StandardMouseEvent(o);"html"===t.target.tagName.toLowerCase()&&this.stopMonitoring(!0)}))),this._hooks.add(dom.addDisposableListener(o.window.document,"mouseover",(o=>{let t=new StandardMouseEvent(o);"html"===t.target.tagName.toLowerCase()&&this.stopMonitoring(!0)}))),this._hooks.add(dom.addDisposableListener(o.window.document.body,"mouseleave",(o=>{this.stopMonitoring(!0)})))}}}