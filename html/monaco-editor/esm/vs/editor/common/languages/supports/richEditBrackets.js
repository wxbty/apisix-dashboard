import*as strings from"../../../../base/common/strings.js";import*as stringBuilder from"../../core/stringBuilder.js";import{Range}from"../../core/range.js";export class RichEditBracket{constructor(t,e,r,n,s,o){this._richEditBracketBrand=void 0,this.languageId=t,this.index=e,this.open=r,this.close=n,this.forwardRegex=s,this.reversedRegex=o,this._openSet=RichEditBracket._toSet(this.open),this._closeSet=RichEditBracket._toSet(this.close)}isOpen(t){return this._openSet.has(t)}isClose(t){return this._closeSet.has(t)}static _toSet(t){const e=new Set;for(const r of t)e.add(r);return e}}function groupFuzzyBrackets(t){const e=t.length;t=t.map((t=>[t[0].toLowerCase(),t[1].toLowerCase()]));const r=[];for(let c=0;c<e;c++)r[c]=c;const n=(t,e)=>{const[r,n]=t,[s,o]=e;return r===s||r===o||n===s||n===o},s=(t,n)=>{const s=Math.min(t,n),o=Math.max(t,n);for(let c=0;c<e;c++)r[c]===o&&(r[c]=s)};for(let c=0;c<e;c++){const o=t[c];for(let i=c+1;i<e;i++){const e=t[i];n(o,e)&&s(r[c],r[i])}}const o=[];for(let c=0;c<e;c++){const n=[],s=[];for(let o=0;o<e;o++)if(r[o]===c){const[e,r]=t[o];n.push(e),s.push(r)}n.length>0&&o.push({open:n,close:s})}return o}export class RichEditBrackets{constructor(t,e){this._richEditBracketsBrand=void 0;const r=groupFuzzyBrackets(e);this.brackets=r.map(((e,n)=>new RichEditBracket(t,n,e.open,e.close,getRegexForBracketPair(e.open,e.close,r,n),getReversedRegexForBracketPair(e.open,e.close,r,n)))),this.forwardRegex=getRegexForBrackets(this.brackets),this.reversedRegex=getReversedRegexForBrackets(this.brackets),this.textIsBracket={},this.textIsOpenBracket={},this.maxBracketLength=0;for(const n of this.brackets){for(const t of n.open)this.textIsBracket[t]=n,this.textIsOpenBracket[t]=!0,this.maxBracketLength=Math.max(this.maxBracketLength,t.length);for(const t of n.close)this.textIsBracket[t]=n,this.textIsOpenBracket[t]=!1,this.maxBracketLength=Math.max(this.maxBracketLength,t.length)}}}function collectSuperstrings(t,e,r,n){for(let s=0,o=e.length;s<o;s++){if(s===r)continue;const o=e[s];for(const e of o.open)e.indexOf(t)>=0&&n.push(e);for(const e of o.close)e.indexOf(t)>=0&&n.push(e)}}function lengthcmp(t,e){return t.length-e.length}function unique(t){if(t.length<=1)return t;const e=[],r=new Set;for(const n of t)r.has(n)||(e.push(n),r.add(n));return e}function getRegexForBracketPair(t,e,r,n){let s=[];s=s.concat(t),s=s.concat(e);for(let o=0,c=s.length;o<c;o++)collectSuperstrings(s[o],r,n,s);return s=unique(s),s.sort(lengthcmp),s.reverse(),createBracketOrRegExp(s)}function getReversedRegexForBracketPair(t,e,r,n){let s=[];s=s.concat(t),s=s.concat(e);for(let o=0,c=s.length;o<c;o++)collectSuperstrings(s[o],r,n,s);return s=unique(s),s.sort(lengthcmp),s.reverse(),createBracketOrRegExp(s.map(toReversedString))}function getRegexForBrackets(t){let e=[];for(const r of t){for(const t of r.open)e.push(t);for(const t of r.close)e.push(t)}return e=unique(e),createBracketOrRegExp(e)}function getReversedRegexForBrackets(t){let e=[];for(const r of t){for(const t of r.open)e.push(t);for(const t of r.close)e.push(t)}return e=unique(e),createBracketOrRegExp(e.map(toReversedString))}function prepareBracketForRegExp(t){const e=/^[\w ]+$/.test(t);return t=strings.escapeRegExpCharacters(t),e?`\\b${t}\\b`:t}function createBracketOrRegExp(t){const e=`(${t.map(prepareBracketForRegExp).join(")|(")})`;return strings.createRegExp(e,!0)}const toReversedString=function(){function t(t){if(stringBuilder.hasTextDecoder){const e=new Uint16Array(t.length);let r=0;for(let n=t.length-1;n>=0;n--)e[r++]=t.charCodeAt(n);return stringBuilder.getPlatformTextDecoder().decode(e)}{const e=[];let r=0;for(let n=t.length-1;n>=0;n--)e[r++]=t.charAt(n);return e.join("")}}let e=null,r=null;return function(n){return e!==n&&(e=n,r=t(e)),r}}();export class BracketsUtils{static _findPrevBracketInText(t,e,r,n){const s=r.match(t);if(!s)return null;const o=r.length-(s.index||0),c=s[0].length,i=n+o;return new Range(e,i-c+1,e,i+1)}static findPrevBracketInRange(t,e,r,n,s){const o=toReversedString(r),c=o.substring(r.length-s,r.length-n);return this._findPrevBracketInText(t,e,c,n)}static findNextBracketInText(t,e,r,n){const s=r.match(t);if(!s)return null;const o=s.index||0,c=s[0].length;if(0===c)return null;const i=n+o;return new Range(e,i+1,e,i+1+c)}static findNextBracketInRange(t,e,r,n,s){const o=r.substring(n,s);return this.findNextBracketInText(t,e,o,n)}}