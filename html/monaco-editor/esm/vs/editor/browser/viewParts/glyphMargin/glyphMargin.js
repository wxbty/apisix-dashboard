import"./glyphMargin.css";import{DynamicViewOverlay}from"../../view/dynamicViewOverlay.js";export class DecorationToRender{constructor(e,t,n){this._decorationToRenderBrand=void 0,this.startLineNumber=+e,this.endLineNumber=+t,this.className=String(n)}}export class DedupOverlay extends DynamicViewOverlay{_render(e,t,n){const r=[];for(let o=e;o<=t;o++){const t=o-e;r[t]=[]}if(0===n.length)return r;n.sort(((e,t)=>e.className===t.className?e.startLineNumber===t.startLineNumber?e.endLineNumber-t.endLineNumber:e.startLineNumber-t.startLineNumber:e.className<t.className?-1:1));let i=null,s=0;for(let o=0,a=n.length;o<a;o++){const a=n[o],h=a.className;let l=Math.max(a.startLineNumber,e)-e;const g=Math.min(a.endLineNumber,t)-e;i===h?(l=Math.max(s+1,l),s=Math.max(s,g)):(i=h,s=g);for(let e=l;e<=s;e++)r[e].push(i)}return r}}export class GlyphMarginOverlay extends DedupOverlay{constructor(e){super(),this._context=e;const t=this._context.configuration.options,n=t.get(131);this._lineHeight=t.get(59),this._glyphMargin=t.get(50),this._glyphMarginLeft=n.glyphMarginLeft,this._glyphMarginWidth=n.glyphMarginWidth,this._renderResult=null,this._context.addEventHandler(this)}dispose(){this._context.removeEventHandler(this),this._renderResult=null,super.dispose()}onConfigurationChanged(e){const t=this._context.configuration.options,n=t.get(131);return this._lineHeight=t.get(59),this._glyphMargin=t.get(50),this._glyphMarginLeft=n.glyphMarginLeft,this._glyphMarginWidth=n.glyphMarginWidth,!0}onDecorationsChanged(e){return!0}onFlushed(e){return!0}onLinesChanged(e){return!0}onLinesDeleted(e){return!0}onLinesInserted(e){return!0}onScrollChanged(e){return e.scrollTopChanged}onZonesChanged(e){return!0}_getDecorations(e){const t=e.getDecorationsInViewport(),n=[];let r=0;for(let i=0,s=t.length;i<s;i++){const e=t[i],s=e.options.glyphMarginClassName;s&&(n[r++]=new DecorationToRender(e.range.startLineNumber,e.range.endLineNumber,s))}return n}prepareRender(e){if(!this._glyphMargin)return void(this._renderResult=null);const t=e.visibleRange.startLineNumber,n=e.visibleRange.endLineNumber,r=this._render(t,n,this._getDecorations(e)),i=this._lineHeight.toString(),s=this._glyphMarginLeft.toString(),o=this._glyphMarginWidth.toString(),a='" style="left:'+s+"px;width:"+o+"px;height:"+i+'px;"></div>',h=[];for(let l=t;l<=n;l++){const e=l-t,n=r[e];0===n.length?h[e]="":h[e]='<div class="cgmr codicon '+n.join(" ")+a}this._renderResult=h}render(e,t){if(!this._renderResult)return"";const n=t-e;return n<0||n>=this._renderResult.length?"":this._renderResult[n]}}