export const MAX_FOLDING_REGIONS=65535;export const MAX_LINE_NUMBER=16777215;const MASK_INDENT=4278190080;export class FoldingRegions{constructor(e,t,n){if(e.length!==t.length||e.length>MAX_FOLDING_REGIONS)throw new Error("invalid startIndexes or endIndexes size");this._startIndexes=e,this._endIndexes=t,this._collapseStates=new Uint32Array(Math.ceil(e.length/32)),this._types=n,this._parentsComputed=!1}ensureParentIndices(){if(!this._parentsComputed){this._parentsComputed=!0;let e=[],t=(t,n)=>{let s=e[e.length-1];return this.getStartLineNumber(s)<=t&&this.getEndLineNumber(s)>=n};for(let n=0,s=this._startIndexes.length;n<s;n++){let s=this._startIndexes[n],r=this._endIndexes[n];if(s>MAX_LINE_NUMBER||r>MAX_LINE_NUMBER)throw new Error("startLineNumber or endLineNumber must not exceed "+MAX_LINE_NUMBER);while(e.length>0&&!t(s,r))e.pop();let i=e.length>0?e[e.length-1]:-1;e.push(n),this._startIndexes[n]=s+((255&i)<<24),this._endIndexes[n]=r+((65280&i)<<16)}}}get length(){return this._startIndexes.length}getStartLineNumber(e){return this._startIndexes[e]&MAX_LINE_NUMBER}getEndLineNumber(e){return this._endIndexes[e]&MAX_LINE_NUMBER}getType(e){return this._types?this._types[e]:void 0}hasTypes(){return!!this._types}isCollapsed(e){let t=e/32|0,n=e%32;return 0!==(this._collapseStates[t]&1<<n)}setCollapsed(e,t){let n=e/32|0,s=e%32,r=this._collapseStates[n];this._collapseStates[n]=t?r|1<<s:r&~(1<<s)}setCollapsedAllOfType(e,t){let n=!1;if(this._types)for(let s=0;s<this._types.length;s++)this._types[s]===e&&(this.setCollapsed(s,t),n=!0);return n}toRegion(e){return new FoldingRegion(this,e)}getParentIndex(e){this.ensureParentIndices();let t=((this._startIndexes[e]&MASK_INDENT)>>>24)+((this._endIndexes[e]&MASK_INDENT)>>>16);return t===MAX_FOLDING_REGIONS?-1:t}contains(e,t){return this.getStartLineNumber(e)<=t&&this.getEndLineNumber(e)>=t}findIndex(e){let t=0,n=this._startIndexes.length;if(0===n)return-1;while(t<n){let s=Math.floor((t+n)/2);e<this.getStartLineNumber(s)?n=s:t=s+1}return t-1}findRange(e){let t=this.findIndex(e);if(t>=0){let n=this.getEndLineNumber(t);if(n>=e)return t;t=this.getParentIndex(t);while(-1!==t){if(this.contains(t,e))return t;t=this.getParentIndex(t)}}return-1}toString(){let e=[];for(let t=0;t<this.length;t++)e[t]=`[${this.isCollapsed(t)?"+":"-"}] ${this.getStartLineNumber(t)}/${this.getEndLineNumber(t)}`;return e.join(", ")}}export class FoldingRegion{constructor(e,t){this.ranges=e,this.index=t}get startLineNumber(){return this.ranges.getStartLineNumber(this.index)}get endLineNumber(){return this.ranges.getEndLineNumber(this.index)}get regionIndex(){return this.index}get parentIndex(){return this.ranges.getParentIndex(this.index)}get isCollapsed(){return this.ranges.isCollapsed(this.index)}containedBy(e){return e.startLineNumber<=this.startLineNumber&&e.endLineNumber>=this.endLineNumber}containsLine(e){return this.startLineNumber<=e&&e<=this.endLineNumber}}