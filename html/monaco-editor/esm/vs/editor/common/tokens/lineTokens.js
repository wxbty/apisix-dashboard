import{TokenMetadata}from"../languages.js";export class LineTokens{constructor(t,e,n){this._lineTokensBrand=void 0,this._tokens=t,this._tokensCount=this._tokens.length>>>1,this._text=e,this._languageIdCodec=n}static createEmpty(t,e){const n=LineTokens.defaultTokenMetadata,s=new Uint32Array(2);return s[0]=t.length,s[1]=n,new LineTokens(s,t,e)}equals(t){return t instanceof LineTokens&&this.slicedEquals(t,0,this._tokensCount)}slicedEquals(t,e,n){if(this._text!==t._text)return!1;if(this._tokensCount!==t._tokensCount)return!1;const s=e<<1,o=s+(n<<1);for(let r=s;r<o;r++)if(this._tokens[r]!==t._tokens[r])return!1;return!0}getLineContent(){return this._text}getCount(){return this._tokensCount}getStartOffset(t){return t>0?this._tokens[t-1<<1]:0}getMetadata(t){const e=this._tokens[1+(t<<1)];return e}getLanguageId(t){const e=this._tokens[1+(t<<1)],n=TokenMetadata.getLanguageId(e);return this._languageIdCodec.decodeLanguageId(n)}getStandardTokenType(t){const e=this._tokens[1+(t<<1)];return TokenMetadata.getTokenType(e)}getForeground(t){const e=this._tokens[1+(t<<1)];return TokenMetadata.getForeground(e)}getClassName(t){const e=this._tokens[1+(t<<1)];return TokenMetadata.getClassNameFromMetadata(e)}getInlineStyle(t,e){const n=this._tokens[1+(t<<1)];return TokenMetadata.getInlineStyleFromMetadata(n,e)}getPresentation(t){const e=this._tokens[1+(t<<1)];return TokenMetadata.getPresentationFromMetadata(e)}getEndOffset(t){return this._tokens[t<<1]}findTokenIndexAtOffset(t){return LineTokens.findIndexInTokensArray(this._tokens,t)}inflate(){return this}sliceAndInflate(t,e,n){return new SliceLineTokens(this,t,e,n)}static convertToEndOffset(t,e){const n=t.length>>>1,s=n-1;for(let o=0;o<s;o++)t[o<<1]=t[o+1<<1];t[s<<1]=e}static findIndexInTokensArray(t,e){if(t.length<=2)return 0;let n=0,s=(t.length>>>1)-1;while(n<s){const o=n+Math.floor((s-n)/2),r=t[o<<1];if(r===e)return o+1;r<e?n=o+1:r>e&&(s=o)}return n}withInserted(t){if(0===t.length)return this;let e=0,n=0,s="";const o=new Array;let r=0;while(1){const i=e<this._tokensCount?this._tokens[e<<1]:-1,a=n<t.length?t[n]:null;if(-1!==i&&(null===a||i<=a.offset)){s+=this._text.substring(r,i);const t=this._tokens[1+(e<<1)];o.push(s.length,t),e++,r=i}else{if(!a)break;if(a.offset>r){s+=this._text.substring(r,a.offset);const t=this._tokens[1+(e<<1)];o.push(s.length,t),r=a.offset}s+=a.text,o.push(s.length,a.tokenMetadata),n++}}return new LineTokens(new Uint32Array(o),s,this._languageIdCodec)}}LineTokens.defaultTokenMetadata=16793600;class SliceLineTokens{constructor(t,e,n,s){this._source=t,this._startOffset=e,this._endOffset=n,this._deltaOffset=s,this._firstTokenIndex=t.findTokenIndexAtOffset(e),this._tokensCount=0;for(let o=this._firstTokenIndex,r=t.getCount();o<r;o++){const e=t.getStartOffset(o);if(e>=n)break;this._tokensCount++}}getMetadata(t){return this._source.getMetadata(this._firstTokenIndex+t)}getLanguageId(t){return this._source.getLanguageId(this._firstTokenIndex+t)}getLineContent(){return this._source.getLineContent().substring(this._startOffset,this._endOffset)}equals(t){return t instanceof SliceLineTokens&&(this._startOffset===t._startOffset&&this._endOffset===t._endOffset&&this._deltaOffset===t._deltaOffset&&this._source.slicedEquals(t._source,this._firstTokenIndex,this._tokensCount))}getCount(){return this._tokensCount}getForeground(t){return this._source.getForeground(this._firstTokenIndex+t)}getEndOffset(t){const e=this._source.getEndOffset(this._firstTokenIndex+t);return Math.min(this._endOffset,e)-this._startOffset+this._deltaOffset}getClassName(t){return this._source.getClassName(this._firstTokenIndex+t)}getInlineStyle(t,e){return this._source.getInlineStyle(this._firstTokenIndex+t,e)}getPresentation(t){return this._source.getPresentation(this._firstTokenIndex+t)}findTokenIndexAtOffset(t){return this._source.findTokenIndexAtOffset(t+this._startOffset-this._deltaOffset)-this._firstTokenIndex}}