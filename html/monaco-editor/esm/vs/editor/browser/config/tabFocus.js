import{Emitter}from"../../../base/common/event.js";class TabFocusImpl{constructor(){this._tabFocus=!1,this._onDidChangeTabFocus=new Emitter,this.onDidChangeTabFocus=this._onDidChangeTabFocus.event}getTabFocusMode(){return this._tabFocus}setTabFocusMode(s){this._tabFocus!==s&&(this._tabFocus=s,this._onDidChangeTabFocus.fire(this._tabFocus))}}export const TabFocus=new TabFocusImpl;