import*as strings from"../../../base/common/strings.js";import{createStringBuilder}from"../core/stringBuilder.js";import{LineDecoration,LineDecorationsNormalizer}from"./lineDecorations.js";class LinePart{constructor(e,t,n){this._linePartBrand=void 0,this.endIndex=e,this.type=t,this.metadata=n}isWhitespace(){return!!(1&this.metadata)}isPseudoAfter(){return!!(4&this.metadata)}}export class LineRange{constructor(e,t){this.startOffset=e,this.endOffset=t}equals(e){return this.startOffset===e.startOffset&&this.endOffset===e.endOffset}}export class RenderLineInput{constructor(e,t,n,r,i,s,a,o,c,h,l,d,p,f,u,g,C,I,L){this.useMonospaceOptimizations=e,this.canUseHalfwidthRightwardsArrow=t,this.lineContent=n,this.continuesWithWrappedLine=r,this.isBasicASCII=i,this.containsRTL=s,this.fauxIndentLength=a,this.lineTokens=o,this.lineDecorations=c.sort(LineDecoration.compare),this.tabSize=h,this.startVisibleColumn=l,this.spaceWidth=d,this.stopRenderingLineAfter=u,this.renderWhitespace="all"===g?4:"boundary"===g?1:"selection"===g?2:"trailing"===g?3:0,this.renderControlCharacters=C,this.fontLigatures=I,this.selectionsOnLine=L&&L.sort(((e,t)=>e.startOffset<t.startOffset?-1:1));const w=Math.abs(f-d),S=Math.abs(p-d);w<S?(this.renderSpaceWidth=f,this.renderSpaceCharCode=11825):(this.renderSpaceWidth=p,this.renderSpaceCharCode=183)}sameSelection(e){if(null===this.selectionsOnLine)return null===e;if(null===e)return!1;if(e.length!==this.selectionsOnLine.length)return!1;for(let t=0;t<this.selectionsOnLine.length;t++)if(!this.selectionsOnLine[t].equals(e[t]))return!1;return!0}equals(e){return this.useMonospaceOptimizations===e.useMonospaceOptimizations&&this.canUseHalfwidthRightwardsArrow===e.canUseHalfwidthRightwardsArrow&&this.lineContent===e.lineContent&&this.continuesWithWrappedLine===e.continuesWithWrappedLine&&this.isBasicASCII===e.isBasicASCII&&this.containsRTL===e.containsRTL&&this.fauxIndentLength===e.fauxIndentLength&&this.tabSize===e.tabSize&&this.startVisibleColumn===e.startVisibleColumn&&this.spaceWidth===e.spaceWidth&&this.renderSpaceWidth===e.renderSpaceWidth&&this.renderSpaceCharCode===e.renderSpaceCharCode&&this.stopRenderingLineAfter===e.stopRenderingLineAfter&&this.renderWhitespace===e.renderWhitespace&&this.renderControlCharacters===e.renderControlCharacters&&this.fontLigatures===e.fontLigatures&&LineDecoration.equalsArr(this.lineDecorations,e.lineDecorations)&&this.lineTokens.equals(e.lineTokens)&&this.sameSelection(e.selectionsOnLine)}}export class DomPosition{constructor(e,t){this.partIndex=e,this.charIndex=t}}export class CharacterMapping{constructor(e,t){this.length=e,this._data=new Uint32Array(this.length),this._absoluteOffsets=new Uint32Array(this.length)}static getPartIndex(e){return(4294901760&e)>>>16}static getCharIndex(e){return(65535&e)>>>0}setColumnInfo(e,t,n,r){const i=(t<<16|n<<0)>>>0;this._data[e-1]=i,this._absoluteOffsets[e-1]=r+n}getAbsoluteOffset(e){return 0===this._absoluteOffsets.length?0:this._absoluteOffsets[e-1]}charOffsetToPartData(e){return 0===this.length?0:e<0?this._data[0]:e>=this.length?this._data[this.length-1]:this._data[e]}getDomPosition(e){const t=this.charOffsetToPartData(e-1),n=CharacterMapping.getPartIndex(t),r=CharacterMapping.getCharIndex(t);return new DomPosition(n,r)}getColumn(e,t){const n=this.partDataToCharOffset(e.partIndex,t,e.charIndex);return n+1}partDataToCharOffset(e,t,n){if(0===this.length)return 0;const r=(e<<16|n<<0)>>>0;let i=0,s=this.length-1;while(i+1<s){const e=i+s>>>1,t=this._data[e];if(t===r)return e;t>r?s=e:i=e}if(i===s)return i;const a=this._data[i],o=this._data[s];if(a===r)return i;if(o===r)return s;const c=CharacterMapping.getPartIndex(a),h=CharacterMapping.getCharIndex(a),l=CharacterMapping.getPartIndex(o);let d;d=c!==l?t:CharacterMapping.getCharIndex(o);const p=n-h,f=d-n;return p<=f?i:s}}export class RenderLineOutput{constructor(e,t,n){this._renderLineOutputBrand=void 0,this.characterMapping=e,this.containsRTL=t,this.containsForeignElements=n}}export function renderViewLine(e,t){if(0===e.lineContent.length){if(e.lineDecorations.length>0){t.appendASCIIString("<span>");let n=0,r=0,i=0;for(const a of e.lineDecorations)1!==a.type&&2!==a.type||(t.appendASCIIString('<span class="'),t.appendASCIIString(a.className),t.appendASCIIString('"></span>'),1===a.type&&(i|=1,n++),2===a.type&&(i|=2,r++));t.appendASCIIString("</span>");const s=new CharacterMapping(1,n+r);return s.setColumnInfo(1,n,0,0),new RenderLineOutput(s,!1,i)}return t.appendASCIIString("<span><span></span></span>"),new RenderLineOutput(new CharacterMapping(0,0),!1,0)}return _renderLine(resolveRenderLineInput(e),t)}export class RenderLineOutput2{constructor(e,t,n,r){this.characterMapping=e,this.html=t,this.containsRTL=n,this.containsForeignElements=r}}export function renderViewLine2(e){const t=createStringBuilder(1e4),n=renderViewLine(e,t);return new RenderLineOutput2(n.characterMapping,t.build(),n.containsRTL,n.containsForeignElements)}class ResolvedRenderLineInput{constructor(e,t,n,r,i,s,a,o,c,h,l,d,p,f,u){this.fontIsMonospace=e,this.canUseHalfwidthRightwardsArrow=t,this.lineContent=n,this.len=r,this.isOverflowing=i,this.parts=s,this.containsForeignElements=a,this.fauxIndentLength=o,this.tabSize=c,this.startVisibleColumn=h,this.containsRTL=l,this.spaceWidth=d,this.renderSpaceCharCode=p,this.renderWhitespace=f,this.renderControlCharacters=u}}function resolveRenderLineInput(e){const t=e.lineContent;let n,r;-1!==e.stopRenderingLineAfter&&e.stopRenderingLineAfter<t.length?(n=!0,r=e.stopRenderingLineAfter):(n=!1,r=t.length);let i=transformAndRemoveOverflowing(e.lineTokens,e.fauxIndentLength,r);e.renderControlCharacters&&!e.isBasicASCII&&(i=extractControlCharacters(t,i)),(4===e.renderWhitespace||1===e.renderWhitespace||2===e.renderWhitespace&&e.selectionsOnLine||3===e.renderWhitespace)&&(i=_applyRenderWhitespace(e,t,r,i));let s=0;if(e.lineDecorations.length>0){for(let t=0,n=e.lineDecorations.length;t<n;t++){const n=e.lineDecorations[t];3===n.type||1===n.type?s|=1:2===n.type&&(s|=2)}i=_applyInlineDecorations(t,r,i,e.lineDecorations)}return e.containsRTL||(i=splitLargeTokens(t,i,!e.isBasicASCII||e.fontLigatures)),new ResolvedRenderLineInput(e.useMonospaceOptimizations,e.canUseHalfwidthRightwardsArrow,t,r,n,i,s,e.fauxIndentLength,e.tabSize,e.startVisibleColumn,e.containsRTL,e.spaceWidth,e.renderSpaceCharCode,e.renderWhitespace,e.renderControlCharacters)}function transformAndRemoveOverflowing(e,t,n){const r=[];let i=0;t>0&&(r[i++]=new LinePart(t,"",0));for(let s=0,a=e.getCount();s<a;s++){const a=e.getEndOffset(s);if(a<=t)continue;const o=e.getClassName(s);if(a>=n){r[i++]=new LinePart(n,o,0);break}r[i++]=new LinePart(a,o,0)}return r}function splitLargeTokens(e,t,n){let r=0;const i=[];let s=0;if(n)for(let a=0,o=t.length;a<o;a++){const n=t[a],o=n.endIndex;if(r+50<o){const t=n.type,a=n.metadata;let c=-1,h=r;for(let n=r;n<o;n++)32===e.charCodeAt(n)&&(c=n),-1!==c&&n-h>=50&&(i[s++]=new LinePart(c+1,t,a),h=c+1,c=-1);h!==o&&(i[s++]=new LinePart(o,t,a))}else i[s++]=n;r=o}else for(let a=0,o=t.length;a<o;a++){const e=t[a],n=e.endIndex,o=n-r;if(o>50){const t=e.type,a=e.metadata,c=Math.ceil(o/50);for(let e=1;e<c;e++){const n=r+50*e;i[s++]=new LinePart(n,t,a)}i[s++]=new LinePart(n,t,a)}else i[s++]=e;r=n}return i}function isControlCharacter(e){return e<32?9!==e:127===e||(e>=8234&&e<=8238||e>=8294&&e<=8297||e>=8206&&e<=8207||1564===e)}function extractControlCharacters(e,t){const n=[];let r=new LinePart(0,"",0),i=0;for(const s of t){const t=s.endIndex;for(;i<t;i++){const t=e.charCodeAt(i);isControlCharacter(t)&&(i>r.endIndex&&(r=new LinePart(i,s.type,s.metadata),n.push(r)),r=new LinePart(i+1,"mtkcontrol",s.metadata),n.push(r))}i>r.endIndex&&(r=new LinePart(t,s.type,s.metadata),n.push(r))}return n}function _applyRenderWhitespace(e,t,n,r){const i=e.continuesWithWrappedLine,s=e.fauxIndentLength,a=e.tabSize,o=e.startVisibleColumn,c=e.useMonospaceOptimizations,h=e.selectionsOnLine,l=1===e.renderWhitespace,d=3===e.renderWhitespace,p=e.renderSpaceWidth!==e.spaceWidth,f=[];let u=0,g=0,C=r[g].type,I=r[g].endIndex;const L=r.length;let w,S=!1,m=strings.firstNonWhitespaceIndex(t);-1===m?(S=!0,m=n,w=n):w=strings.lastNonWhitespaceIndex(t);let A=!1,O=0,x=h&&h[O],R=o%a;for(let P=s;P<n;P++){const e=t.charCodeAt(P);let i;if(x&&P>=x.endOffset&&(O++,x=h&&h[O]),P<m||P>w)i=!0;else if(9===e)i=!0;else if(32===e)if(l)if(A)i=!0;else{const e=P+1<n?t.charCodeAt(P+1):0;i=32===e||9===e}else i=!0;else i=!1;if(i&&h&&(i=!!x&&x.startOffset<=P&&x.endOffset>P),i&&d&&(i=S||P>w),A){if(!i||!c&&R>=a){if(p){const e=u>0?f[u-1].endIndex:s;for(let t=e+1;t<=P;t++)f[u++]=new LinePart(t,"mtkw",1)}else f[u++]=new LinePart(P,"mtkw",1);R%=a}}else(P===I||i&&P>s)&&(f[u++]=new LinePart(P,C,0),R%=a);9===e?R=a:strings.isFullWidthCharacter(e)?R+=2:R++,A=i;while(P===I){if(g++,!(g<L))break;C=r[g].type,I=r[g].endIndex}}let W=!1;if(A)if(i&&l){const e=n>0?t.charCodeAt(n-1):0,r=n>1?t.charCodeAt(n-2):0,i=32===e&&32!==r&&9!==r;i||(W=!0)}else W=!0;if(W)if(p){const e=u>0?f[u-1].endIndex:s;for(let t=e+1;t<=n;t++)f[u++]=new LinePart(t,"mtkw",1)}else f[u++]=new LinePart(n,"mtkw",1);else f[u++]=new LinePart(n,C,0);return f}function _applyInlineDecorations(e,t,n,r){r.sort(LineDecoration.compare);const i=LineDecorationsNormalizer.normalize(e,r),s=i.length;let a=0;const o=[];let c=0,h=0;for(let d=0,p=n.length;d<p;d++){const e=n[d],t=e.endIndex,r=e.type,l=e.metadata;while(a<s&&i[a].startOffset<t){const e=i[a];if(e.startOffset>h&&(h=e.startOffset,o[c++]=new LinePart(h,r,l)),!(e.endOffset+1<=t)){h=t,o[c++]=new LinePart(h,r+" "+e.className,l|e.metadata);break}h=e.endOffset+1,o[c++]=new LinePart(h,r+" "+e.className,l|e.metadata),a++}t>h&&(h=t,o[c++]=new LinePart(h,r,l))}const l=n[n.length-1].endIndex;if(a<s&&i[a].startOffset===l)while(a<s&&i[a].startOffset===l){const e=i[a];o[c++]=new LinePart(h,e.className,e.metadata),a++}return o}function _renderLine(e,t){const n=e.fontIsMonospace,r=e.canUseHalfwidthRightwardsArrow,i=e.containsForeignElements,s=e.lineContent,a=e.len,o=e.isOverflowing,c=e.parts,h=e.fauxIndentLength,l=e.tabSize,d=e.startVisibleColumn,p=e.containsRTL,f=e.spaceWidth,u=e.renderSpaceCharCode,g=e.renderWhitespace,C=e.renderControlCharacters,I=new CharacterMapping(a+1,c.length);let L=!1,w=0,S=d,m=0,A=0,O=0,x=0;p?t.appendASCIIString('<span dir="ltr">'):t.appendASCIIString("<span>");for(let R=0,W=c.length;R<W;R++){x+=O;const e=c[R],o=e.endIndex,d=e.type,p=0!==g&&e.isWhitespace(),W=p&&!n&&("mtkw"===d||!i),P=w===o&&e.isPseudoAfter();if(m=0,t.appendASCIIString('<span class="'),t.appendASCIIString(W?"mtkz":d),t.appendASCII(34),p){let e=0;{let t=w,n=S;for(;t<o;t++){const r=s.charCodeAt(t),i=0|(9===r?l-n%l:1);e+=i,t>=h&&(n+=i)}}for(W&&(t.appendASCIIString(' style="width:'),t.appendASCIIString(String(f*e)),t.appendASCIIString('px"')),t.appendASCII(62);w<o;w++){I.setColumnInfo(w+1,R-A,m,x),A=0;const e=s.charCodeAt(w);let n;if(9===e){n=l-S%l|0,!r||n>1?t.write1(8594):t.write1(65515);for(let e=2;e<=n;e++)t.write1(160)}else n=1,t.write1(u);m+=n,w>=h&&(S+=n)}O=e}else{let e=0;for(t.appendASCII(62);w<o;w++){I.setColumnInfo(w+1,R-A,m,x),A=0;const n=s.charCodeAt(w);let r=1,i=1;switch(n){case 9:r=l-S%l,i=r;for(let e=1;e<=r;e++)t.write1(160);break;case 32:t.write1(160);break;case 60:t.appendASCIIString("&lt;");break;case 62:t.appendASCIIString("&gt;");break;case 38:t.appendASCIIString("&amp;");break;case 0:C?t.write1(9216):t.appendASCIIString("&#00;");break;case 65279:case 8232:case 8233:case 133:t.write1(65533);break;default:strings.isFullWidthCharacter(n)&&i++,C&&n<32?t.write1(9216+n):C&&127===n?t.write1(9249):C&&isControlCharacter(n)?(t.appendASCIIString("[U+"),t.appendASCIIString(to4CharHex(n)),t.appendASCIIString("]"),r=8):t.write1(n)}m+=r,e+=r,w>=h&&(S+=i)}O=e}P?A++:A=0,w>=a&&!L&&e.isPseudoAfter()&&(L=!0,I.setColumnInfo(w+1,R,m,x)),t.appendASCIIString("</span>")}return L||I.setColumnInfo(a+1,c.length-1,m,x),o&&t.appendASCIIString("<span>&hellip;</span>"),t.appendASCIIString("</span>"),new RenderLineOutput(I,p,i)}function to4CharHex(e){return e.toString(16).toUpperCase().padStart(4,"0")}