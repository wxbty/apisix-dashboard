import{Position}from"../../core/position.js";import{Range}from"../../core/range.js";import{FindMatch}from"../../model.js";import{SENTINEL,TreeNode,fixInsert,leftest,rbDelete,righttest,updateTreeMetadata}from"./rbTreeBase.js";import{Searcher,createFindMatch,isValidMatch}from"../textModelSearch.js";export const AverageBufferSize=65535;export function createUintArray(e){let t;return t=e[e.length-1]<65536?new Uint16Array(e.length):new Uint32Array(e.length),t.set(e,0),t}export class LineStarts{constructor(e,t,n,i,s){this.lineStarts=e,this.cr=t,this.lf=n,this.crlf=i,this.isBasicASCII=s}}export function createLineStartsFast(e,t=!0){const n=[0];let i=1;for(let s=0,r=e.length;s<r;s++){const t=e.charCodeAt(s);13===t?s+1<r&&10===e.charCodeAt(s+1)?(n[i++]=s+2,s++):n[i++]=s+1:10===t&&(n[i++]=s+1)}return t?createUintArray(n):n}export function createLineStarts(e,t){e.length=0,e[0]=0;let n=1,i=0,s=0,r=0,f=!0;for(let l=0,o=t.length;l<o;l++){const h=t.charCodeAt(l);13===h?l+1<o&&10===t.charCodeAt(l+1)?(r++,e[n++]=l+2,l++):(i++,e[n++]=l+1):10===h?(s++,e[n++]=l+1):f&&9!==h&&(h<32||h>126)&&(f=!1)}const h=new LineStarts(createUintArray(e),i,s,r,f);return e.length=0,h}export class Piece{constructor(e,t,n,i,s){this.bufferIndex=e,this.start=t,this.end=n,this.lineFeedCnt=i,this.length=s}}export class StringBuffer{constructor(e,t){this.buffer=e,this.lineStarts=t}}class PieceTreeSnapshot{constructor(e,t){this._pieces=[],this._tree=e,this._BOM=t,this._index=0,e.root!==SENTINEL&&e.iterate(e.root,(e=>(e!==SENTINEL&&this._pieces.push(e.piece),!0)))}read(){return 0===this._pieces.length?0===this._index?(this._index++,this._BOM):null:this._index>this._pieces.length-1?null:0===this._index?this._BOM+this._tree.getPieceContent(this._pieces[this._index++]):this._tree.getPieceContent(this._pieces[this._index++])}}class PieceTreeSearchCache{constructor(e){this._limit=e,this._cache=[]}get(e){for(let t=this._cache.length-1;t>=0;t--){const n=this._cache[t];if(n.nodeStartOffset<=e&&n.nodeStartOffset+n.node.piece.length>=e)return n}return null}get2(e){for(let t=this._cache.length-1;t>=0;t--){const n=this._cache[t];if(n.nodeStartLineNumber&&n.nodeStartLineNumber<e&&n.nodeStartLineNumber+n.node.piece.lineFeedCnt>=e)return n}return null}set(e){this._cache.length>=this._limit&&this._cache.shift(),this._cache.push(e)}validate(e){let t=!1;const n=this._cache;for(let i=0;i<n.length;i++){const s=n[i];(null===s.node.parent||s.nodeStartOffset>=e)&&(n[i]=null,t=!0)}if(t){const e=[];for(const t of n)null!==t&&e.push(t);this._cache=e}}}export class PieceTreeBase{constructor(e,t,n){this.create(e,t,n)}create(e,t,n){this._buffers=[new StringBuffer("",[0])],this._lastChangeBufferPos={line:0,column:0},this.root=SENTINEL,this._lineCnt=1,this._length=0,this._EOL=t,this._EOLLength=t.length,this._EOLNormalized=n;let i=null;for(let s=0,r=e.length;s<r;s++)if(e[s].buffer.length>0){e[s].lineStarts||(e[s].lineStarts=createLineStartsFast(e[s].buffer));const t=new Piece(s+1,{line:0,column:0},{line:e[s].lineStarts.length-1,column:e[s].buffer.length-e[s].lineStarts[e[s].lineStarts.length-1]},e[s].lineStarts.length-1,e[s].buffer.length);this._buffers.push(e[s]),i=this.rbInsertRight(i,t)}this._searchCache=new PieceTreeSearchCache(1),this._lastVisitedLine={lineNumber:0,value:""},this.computeBufferMetadata()}normalizeEOL(e){const t=AverageBufferSize,n=t-Math.floor(t/3),i=2*n;let s="",r=0;const f=[];if(this.iterate(this.root,(t=>{const h=this.getNodeContent(t),l=h.length;if(r<=n||r+l<i)return s+=h,r+=l,!0;const o=s.replace(/\r\n|\r|\n/g,e);return f.push(new StringBuffer(o,createLineStartsFast(o))),s=h,r=l,!0})),r>0){const t=s.replace(/\r\n|\r|\n/g,e);f.push(new StringBuffer(t,createLineStartsFast(t)))}this.create(f,e,!0)}getEOL(){return this._EOL}setEOL(e){this._EOL=e,this._EOLLength=this._EOL.length,this.normalizeEOL(e)}createSnapshot(e){return new PieceTreeSnapshot(this,e)}getOffsetAt(e,t){let n=0,i=this.root;while(i!==SENTINEL)if(i.left!==SENTINEL&&i.lf_left+1>=e)i=i.left;else{if(i.lf_left+i.piece.lineFeedCnt+1>=e){n+=i.size_left;const s=this.getAccumulatedValue(i,e-i.lf_left-2);return n+(s+t-1)}e-=i.lf_left+i.piece.lineFeedCnt,n+=i.size_left+i.piece.length,i=i.right}return n}getPositionAt(e){e=Math.floor(e),e=Math.max(0,e);let t=this.root,n=0;const i=e;while(t!==SENTINEL)if(0!==t.size_left&&t.size_left>=e)t=t.left;else{if(t.size_left+t.piece.length>=e){const s=this.getIndexOf(t,e-t.size_left);if(n+=t.lf_left+s.index,0===s.index){const e=this.getOffsetAt(n+1,1),t=i-e;return new Position(n+1,t+1)}return new Position(n+1,s.remainder+1)}if(e-=t.size_left+t.piece.length,n+=t.lf_left+t.piece.lineFeedCnt,t.right===SENTINEL){const t=this.getOffsetAt(n+1,1),s=i-e-t;return new Position(n+1,s+1)}t=t.right}return new Position(1,1)}getValueInRange(e,t){if(e.startLineNumber===e.endLineNumber&&e.startColumn===e.endColumn)return"";const n=this.nodeAt2(e.startLineNumber,e.startColumn),i=this.nodeAt2(e.endLineNumber,e.endColumn),s=this.getValueInRange2(n,i);return t?t===this._EOL&&this._EOLNormalized&&t===this.getEOL()&&this._EOLNormalized?s:s.replace(/\r\n|\r|\n/g,t):s}getValueInRange2(e,t){if(e.node===t.node){const n=e.node,i=this._buffers[n.piece.bufferIndex].buffer,s=this.offsetInBuffer(n.piece.bufferIndex,n.piece.start);return i.substring(s+e.remainder,s+t.remainder)}let n=e.node;const i=this._buffers[n.piece.bufferIndex].buffer,s=this.offsetInBuffer(n.piece.bufferIndex,n.piece.start);let r=i.substring(s+e.remainder,s+n.piece.length);n=n.next();while(n!==SENTINEL){const e=this._buffers[n.piece.bufferIndex].buffer,i=this.offsetInBuffer(n.piece.bufferIndex,n.piece.start);if(n===t.node){r+=e.substring(i,i+t.remainder);break}r+=e.substr(i,n.piece.length),n=n.next()}return r}getLinesContent(){const e=[];let t=0,n="",i=!1;return this.iterate(this.root,(s=>{if(s===SENTINEL)return!0;const r=s.piece;let f=r.length;if(0===f)return!0;const h=this._buffers[r.bufferIndex].buffer,l=this._buffers[r.bufferIndex].lineStarts,o=r.start.line,u=r.end.line;let a=l[o]+r.start.column;if(i&&(10===h.charCodeAt(a)&&(a++,f--),e[t++]=n,n="",i=!1,0===f))return!0;if(o===u)return this._EOLNormalized||13!==h.charCodeAt(a+f-1)?n+=h.substr(a,f):(i=!0,n+=h.substr(a,f-1)),!0;n+=this._EOLNormalized?h.substring(a,Math.max(a,l[o+1]-this._EOLLength)):h.substring(a,l[o+1]).replace(/(\r\n|\r|\n)$/,""),e[t++]=n;for(let i=o+1;i<u;i++)n=this._EOLNormalized?h.substring(l[i],l[i+1]-this._EOLLength):h.substring(l[i],l[i+1]).replace(/(\r\n|\r|\n)$/,""),e[t++]=n;return this._EOLNormalized||13!==h.charCodeAt(l[u]+r.end.column-1)?n=h.substr(l[u],r.end.column):(i=!0,0===r.end.column?t--:n=h.substr(l[u],r.end.column-1)),!0})),i&&(e[t++]=n,n=""),e[t++]=n,e}getLength(){return this._length}getLineCount(){return this._lineCnt}getLineContent(e){return this._lastVisitedLine.lineNumber===e||(this._lastVisitedLine.lineNumber=e,e===this._lineCnt?this._lastVisitedLine.value=this.getLineRawContent(e):this._EOLNormalized?this._lastVisitedLine.value=this.getLineRawContent(e,this._EOLLength):this._lastVisitedLine.value=this.getLineRawContent(e).replace(/(\r\n|\r|\n)$/,"")),this._lastVisitedLine.value}_getCharCode(e){if(e.remainder===e.node.piece.length){const t=e.node.next();if(!t)return 0;const n=this._buffers[t.piece.bufferIndex],i=this.offsetInBuffer(t.piece.bufferIndex,t.piece.start);return n.buffer.charCodeAt(i)}{const t=this._buffers[e.node.piece.bufferIndex],n=this.offsetInBuffer(e.node.piece.bufferIndex,e.node.piece.start),i=n+e.remainder;return t.buffer.charCodeAt(i)}}getLineCharCode(e,t){const n=this.nodeAt2(e,t+1);return this._getCharCode(n)}getLineLength(e){if(e===this.getLineCount()){const t=this.getOffsetAt(e,1);return this.getLength()-t}return this.getOffsetAt(e+1,1)-this.getOffsetAt(e,1)-this._EOLLength}findMatchesInNode(e,t,n,i,s,r,f,h,l,o,u){const a=this._buffers[e.piece.bufferIndex],c=this.offsetInBuffer(e.piece.bufferIndex,e.piece.start),d=this.offsetInBuffer(e.piece.bufferIndex,s),g=this.offsetInBuffer(e.piece.bufferIndex,r);let p;const b={line:0,column:0};let _,I;t._wordSeparators?(_=a.buffer.substring(d,g),I=e=>e+d,t.reset(0)):(_=a.buffer,I=e=>e,t.reset(d));do{if(p=t.next(_),p){if(I(p.index)>=g)return o;this.positionInBuffer(e,I(p.index)-c,b);const t=this.getLineFeedCnt(e.piece.bufferIndex,s,b),r=b.line===s.line?b.column-s.column+i:b.column+1,f=r+p[0].length;if(u[o++]=createFindMatch(new Range(n+t,r,n+t,f),p,h),I(p.index)+p[0].length>=g)return o;if(o>=l)return o}}while(p);return o}findMatchesLineByLine(e,t,n,i){const s=[];let r=0;const f=new Searcher(t.wordSeparators,t.regex);let h=this.nodeAt2(e.startLineNumber,e.startColumn);if(null===h)return[];const l=this.nodeAt2(e.endLineNumber,e.endColumn);if(null===l)return[];let o=this.positionInBuffer(h.node,h.remainder);const u=this.positionInBuffer(l.node,l.remainder);if(h.node===l.node)return this.findMatchesInNode(h.node,f,e.startLineNumber,e.startColumn,o,u,t,n,i,r,s),s;let a=e.startLineNumber,c=h.node;while(c!==l.node){const l=this.getLineFeedCnt(c.piece.bufferIndex,o,c.piece.end);if(l>=1){const h=this._buffers[c.piece.bufferIndex].lineStarts,u=this.offsetInBuffer(c.piece.bufferIndex,c.piece.start),d=h[o.line+l],g=a===e.startLineNumber?e.startColumn:1;if(r=this.findMatchesInNode(c,f,a,g,o,this.positionInBuffer(c,d-u),t,n,i,r,s),r>=i)return s;a+=l}const u=a===e.startLineNumber?e.startColumn-1:0;if(a===e.endLineNumber){const h=this.getLineContent(a).substring(u,e.endColumn-1);return r=this._findMatchesInLine(t,f,h,e.endLineNumber,u,r,s,n,i),s}if(r=this._findMatchesInLine(t,f,this.getLineContent(a).substr(u),a,u,r,s,n,i),r>=i)return s;a++,h=this.nodeAt2(a,1),c=h.node,o=this.positionInBuffer(h.node,h.remainder)}if(a===e.endLineNumber){const h=a===e.startLineNumber?e.startColumn-1:0,l=this.getLineContent(a).substring(h,e.endColumn-1);return r=this._findMatchesInLine(t,f,l,e.endLineNumber,h,r,s,n,i),s}const d=a===e.startLineNumber?e.startColumn:1;return r=this.findMatchesInNode(l.node,f,a,d,o,u,t,n,i,r,s),s}_findMatchesInLine(e,t,n,i,s,r,f,h,l){const o=e.wordSeparators;if(!h&&e.simpleSearch){const t=e.simpleSearch,h=t.length,u=n.length;let a=-h;while(-1!==(a=n.indexOf(t,a+h)))if((!o||isValidMatch(o,n,u,a,h))&&(f[r++]=new FindMatch(new Range(i,a+1+s,i,a+1+h+s),null),r>=l))return r;return r}let u;t.reset(0);do{if(u=t.next(n),u&&(f[r++]=createFindMatch(new Range(i,u.index+1+s,i,u.index+1+u[0].length+s),u,h),r>=l))return r}while(u);return r}insert(e,t,n=!1){if(this._EOLNormalized=this._EOLNormalized&&n,this._lastVisitedLine.lineNumber=0,this._lastVisitedLine.value="",this.root!==SENTINEL){const{node:n,remainder:i,nodeStartOffset:s}=this.nodeAt(e),r=n.piece,f=r.bufferIndex,h=this.positionInBuffer(n,i);if(0===n.piece.bufferIndex&&r.end.line===this._lastChangeBufferPos.line&&r.end.column===this._lastChangeBufferPos.column&&s+r.length===e&&t.length<AverageBufferSize)return this.appendToNode(n,t),void this.computeBufferMetadata();if(s===e)this.insertContentToNodeLeft(t,n),this._searchCache.validate(e);else if(s+n.piece.length>e){const e=[];let s=new Piece(r.bufferIndex,h,r.end,this.getLineFeedCnt(r.bufferIndex,h,r.end),this.offsetInBuffer(f,r.end)-this.offsetInBuffer(f,h));if(this.shouldCheckCRLF()&&this.endWithCR(t)){const e=this.nodeCharCodeAt(n,i);if(10===e){const e={line:s.start.line+1,column:0};s=new Piece(s.bufferIndex,e,s.end,this.getLineFeedCnt(s.bufferIndex,e,s.end),s.length-1),t+="\n"}}if(this.shouldCheckCRLF()&&this.startWithLF(t)){const s=this.nodeCharCodeAt(n,i-1);if(13===s){const s=this.positionInBuffer(n,i-1);this.deleteNodeTail(n,s),t="\r"+t,0===n.piece.length&&e.push(n)}else this.deleteNodeTail(n,h)}else this.deleteNodeTail(n,h);const l=this.createNewPieces(t);s.length>0&&this.rbInsertRight(n,s);let o=n;for(let t=0;t<l.length;t++)o=this.rbInsertRight(o,l[t]);this.deleteNodes(e)}else this.insertContentToNodeRight(t,n)}else{const e=this.createNewPieces(t);let n=this.rbInsertLeft(null,e[0]);for(let t=1;t<e.length;t++)n=this.rbInsertRight(n,e[t])}this.computeBufferMetadata()}delete(e,t){if(this._lastVisitedLine.lineNumber=0,this._lastVisitedLine.value="",t<=0||this.root===SENTINEL)return;const n=this.nodeAt(e),i=this.nodeAt(e+t),s=n.node,r=i.node;if(s===r){const r=this.positionInBuffer(s,n.remainder),f=this.positionInBuffer(s,i.remainder);if(n.nodeStartOffset===e){if(t===s.piece.length){const e=s.next();return rbDelete(this,s),this.validateCRLFWithPrevNode(e),void this.computeBufferMetadata()}return this.deleteNodeHead(s,f),this._searchCache.validate(e),this.validateCRLFWithPrevNode(s),void this.computeBufferMetadata()}return n.nodeStartOffset+s.piece.length===e+t?(this.deleteNodeTail(s,r),this.validateCRLFWithNextNode(s),void this.computeBufferMetadata()):(this.shrinkNode(s,r,f),void this.computeBufferMetadata())}const f=[],h=this.positionInBuffer(s,n.remainder);this.deleteNodeTail(s,h),this._searchCache.validate(e),0===s.piece.length&&f.push(s);const l=this.positionInBuffer(r,i.remainder);this.deleteNodeHead(r,l),0===r.piece.length&&f.push(r);const o=s.next();for(let a=o;a!==SENTINEL&&a!==r;a=a.next())f.push(a);const u=0===s.piece.length?s.prev():s;this.deleteNodes(f),this.validateCRLFWithNextNode(u),this.computeBufferMetadata()}insertContentToNodeLeft(e,t){const n=[];if(this.shouldCheckCRLF()&&this.endWithCR(e)&&this.startWithLF(t)){const i=t.piece,s={line:i.start.line+1,column:0},r=new Piece(i.bufferIndex,s,i.end,this.getLineFeedCnt(i.bufferIndex,s,i.end),i.length-1);t.piece=r,e+="\n",updateTreeMetadata(this,t,-1,-1),0===t.piece.length&&n.push(t)}const i=this.createNewPieces(e);let s=this.rbInsertLeft(t,i[i.length-1]);for(let r=i.length-2;r>=0;r--)s=this.rbInsertLeft(s,i[r]);this.validateCRLFWithPrevNode(s),this.deleteNodes(n)}insertContentToNodeRight(e,t){this.adjustCarriageReturnFromNext(e,t)&&(e+="\n");const n=this.createNewPieces(e),i=this.rbInsertRight(t,n[0]);let s=i;for(let r=1;r<n.length;r++)s=this.rbInsertRight(s,n[r]);this.validateCRLFWithPrevNode(i)}positionInBuffer(e,t,n){const i=e.piece,s=e.piece.bufferIndex,r=this._buffers[s].lineStarts,f=r[i.start.line]+i.start.column,h=f+t;let l=i.start.line,o=i.end.line,u=0,a=0,c=0;while(l<=o){if(u=l+(o-l)/2|0,c=r[u],u===o)break;if(a=r[u+1],h<c)o=u-1;else{if(!(h>=a))break;l=u+1}}return n?(n.line=u,n.column=h-c,null):{line:u,column:h-c}}getLineFeedCnt(e,t,n){if(0===n.column)return n.line-t.line;const i=this._buffers[e].lineStarts;if(n.line===i.length-1)return n.line-t.line;const s=i[n.line+1],r=i[n.line]+n.column;if(s>r+1)return n.line-t.line;const f=r-1,h=this._buffers[e].buffer;return 13===h.charCodeAt(f)?n.line-t.line+1:n.line-t.line}offsetInBuffer(e,t){const n=this._buffers[e].lineStarts;return n[t.line]+t.column}deleteNodes(e){for(let t=0;t<e.length;t++)rbDelete(this,e[t])}createNewPieces(e){if(e.length>AverageBufferSize){const t=[];while(e.length>AverageBufferSize){const n=e.charCodeAt(AverageBufferSize-1);let i;13===n||n>=55296&&n<=56319?(i=e.substring(0,AverageBufferSize-1),e=e.substring(AverageBufferSize-1)):(i=e.substring(0,AverageBufferSize),e=e.substring(AverageBufferSize));const s=createLineStartsFast(i);t.push(new Piece(this._buffers.length,{line:0,column:0},{line:s.length-1,column:i.length-s[s.length-1]},s.length-1,i.length)),this._buffers.push(new StringBuffer(i,s))}const n=createLineStartsFast(e);return t.push(new Piece(this._buffers.length,{line:0,column:0},{line:n.length-1,column:e.length-n[n.length-1]},n.length-1,e.length)),this._buffers.push(new StringBuffer(e,n)),t}let t=this._buffers[0].buffer.length;const n=createLineStartsFast(e,!1);let i=this._lastChangeBufferPos;if(this._buffers[0].lineStarts[this._buffers[0].lineStarts.length-1]===t&&0!==t&&this.startWithLF(e)&&this.endWithCR(this._buffers[0].buffer)){this._lastChangeBufferPos={line:this._lastChangeBufferPos.line,column:this._lastChangeBufferPos.column+1},i=this._lastChangeBufferPos;for(let e=0;e<n.length;e++)n[e]+=t+1;this._buffers[0].lineStarts=this._buffers[0].lineStarts.concat(n.slice(1)),this._buffers[0].buffer+="_"+e,t+=1}else{if(0!==t)for(let e=0;e<n.length;e++)n[e]+=t;this._buffers[0].lineStarts=this._buffers[0].lineStarts.concat(n.slice(1)),this._buffers[0].buffer+=e}const s=this._buffers[0].buffer.length,r=this._buffers[0].lineStarts.length-1,f=s-this._buffers[0].lineStarts[r],h={line:r,column:f},l=new Piece(0,i,h,this.getLineFeedCnt(0,i,h),s-t);return this._lastChangeBufferPos=h,[l]}getLineRawContent(e,t=0){let n=this.root,i="";const s=this._searchCache.get2(e);if(s){n=s.node;const r=this.getAccumulatedValue(n,e-s.nodeStartLineNumber-1),f=this._buffers[n.piece.bufferIndex].buffer,h=this.offsetInBuffer(n.piece.bufferIndex,n.piece.start);if(s.nodeStartLineNumber+n.piece.lineFeedCnt!==e){const i=this.getAccumulatedValue(n,e-s.nodeStartLineNumber);return f.substring(h+r,h+i-t)}i=f.substring(h+r,h+n.piece.length)}else{let s=0;const r=e;while(n!==SENTINEL)if(n.left!==SENTINEL&&n.lf_left>=e-1)n=n.left;else{if(n.lf_left+n.piece.lineFeedCnt>e-1){const i=this.getAccumulatedValue(n,e-n.lf_left-2),f=this.getAccumulatedValue(n,e-n.lf_left-1),h=this._buffers[n.piece.bufferIndex].buffer,l=this.offsetInBuffer(n.piece.bufferIndex,n.piece.start);return s+=n.size_left,this._searchCache.set({node:n,nodeStartOffset:s,nodeStartLineNumber:r-(e-1-n.lf_left)}),h.substring(l+i,l+f-t)}if(n.lf_left+n.piece.lineFeedCnt===e-1){const t=this.getAccumulatedValue(n,e-n.lf_left-2),s=this._buffers[n.piece.bufferIndex].buffer,r=this.offsetInBuffer(n.piece.bufferIndex,n.piece.start);i=s.substring(r+t,r+n.piece.length);break}e-=n.lf_left+n.piece.lineFeedCnt,s+=n.size_left+n.piece.length,n=n.right}}n=n.next();while(n!==SENTINEL){const e=this._buffers[n.piece.bufferIndex].buffer;if(n.piece.lineFeedCnt>0){const s=this.getAccumulatedValue(n,0),r=this.offsetInBuffer(n.piece.bufferIndex,n.piece.start);return i+=e.substring(r,r+s-t),i}{const t=this.offsetInBuffer(n.piece.bufferIndex,n.piece.start);i+=e.substr(t,n.piece.length)}n=n.next()}return i}computeBufferMetadata(){let e=this.root,t=1,n=0;while(e!==SENTINEL)t+=e.lf_left+e.piece.lineFeedCnt,n+=e.size_left+e.piece.length,e=e.right;this._lineCnt=t,this._length=n,this._searchCache.validate(this._length)}getIndexOf(e,t){const n=e.piece,i=this.positionInBuffer(e,t),s=i.line-n.start.line;if(this.offsetInBuffer(n.bufferIndex,n.end)-this.offsetInBuffer(n.bufferIndex,n.start)===t){const t=this.getLineFeedCnt(e.piece.bufferIndex,n.start,i);if(t!==s)return{index:t,remainder:0}}return{index:s,remainder:i.column}}getAccumulatedValue(e,t){if(t<0)return 0;const n=e.piece,i=this._buffers[n.bufferIndex].lineStarts,s=n.start.line+t+1;return s>n.end.line?i[n.end.line]+n.end.column-i[n.start.line]-n.start.column:i[s]-i[n.start.line]-n.start.column}deleteNodeTail(e,t){const n=e.piece,i=n.lineFeedCnt,s=this.offsetInBuffer(n.bufferIndex,n.end),r=t,f=this.offsetInBuffer(n.bufferIndex,r),h=this.getLineFeedCnt(n.bufferIndex,n.start,r),l=h-i,o=f-s,u=n.length+o;e.piece=new Piece(n.bufferIndex,n.start,r,h,u),updateTreeMetadata(this,e,o,l)}deleteNodeHead(e,t){const n=e.piece,i=n.lineFeedCnt,s=this.offsetInBuffer(n.bufferIndex,n.start),r=t,f=this.getLineFeedCnt(n.bufferIndex,r,n.end),h=this.offsetInBuffer(n.bufferIndex,r),l=f-i,o=s-h,u=n.length+o;e.piece=new Piece(n.bufferIndex,r,n.end,f,u),updateTreeMetadata(this,e,o,l)}shrinkNode(e,t,n){const i=e.piece,s=i.start,r=i.end,f=i.length,h=i.lineFeedCnt,l=t,o=this.getLineFeedCnt(i.bufferIndex,i.start,l),u=this.offsetInBuffer(i.bufferIndex,t)-this.offsetInBuffer(i.bufferIndex,s);e.piece=new Piece(i.bufferIndex,i.start,l,o,u),updateTreeMetadata(this,e,u-f,o-h);const a=new Piece(i.bufferIndex,n,r,this.getLineFeedCnt(i.bufferIndex,n,r),this.offsetInBuffer(i.bufferIndex,r)-this.offsetInBuffer(i.bufferIndex,n)),c=this.rbInsertRight(e,a);this.validateCRLFWithPrevNode(c)}appendToNode(e,t){this.adjustCarriageReturnFromNext(t,e)&&(t+="\n");const n=this.shouldCheckCRLF()&&this.startWithLF(t)&&this.endWithCR(e),i=this._buffers[0].buffer.length;this._buffers[0].buffer+=t;const s=createLineStartsFast(t,!1);for(let c=0;c<s.length;c++)s[c]+=i;if(n){const e=this._buffers[0].lineStarts[this._buffers[0].lineStarts.length-2];this._buffers[0].lineStarts.pop(),this._lastChangeBufferPos={line:this._lastChangeBufferPos.line-1,column:i-e}}this._buffers[0].lineStarts=this._buffers[0].lineStarts.concat(s.slice(1));const r=this._buffers[0].lineStarts.length-1,f=this._buffers[0].buffer.length-this._buffers[0].lineStarts[r],h={line:r,column:f},l=e.piece.length+t.length,o=e.piece.lineFeedCnt,u=this.getLineFeedCnt(0,e.piece.start,h),a=u-o;e.piece=new Piece(e.piece.bufferIndex,e.piece.start,h,u,l),this._lastChangeBufferPos=h,updateTreeMetadata(this,e,t.length,a)}nodeAt(e){let t=this.root;const n=this._searchCache.get(e);if(n)return{node:n.node,nodeStartOffset:n.nodeStartOffset,remainder:e-n.nodeStartOffset};let i=0;while(t!==SENTINEL)if(t.size_left>e)t=t.left;else{if(t.size_left+t.piece.length>=e){i+=t.size_left;const n={node:t,remainder:e-t.size_left,nodeStartOffset:i};return this._searchCache.set(n),n}e-=t.size_left+t.piece.length,i+=t.size_left+t.piece.length,t=t.right}return null}nodeAt2(e,t){let n=this.root,i=0;while(n!==SENTINEL)if(n.left!==SENTINEL&&n.lf_left>=e-1)n=n.left;else{if(n.lf_left+n.piece.lineFeedCnt>e-1){const s=this.getAccumulatedValue(n,e-n.lf_left-2),r=this.getAccumulatedValue(n,e-n.lf_left-1);return i+=n.size_left,{node:n,remainder:Math.min(s+t-1,r),nodeStartOffset:i}}if(n.lf_left+n.piece.lineFeedCnt===e-1){const s=this.getAccumulatedValue(n,e-n.lf_left-2);if(s+t-1<=n.piece.length)return{node:n,remainder:s+t-1,nodeStartOffset:i};t-=n.piece.length-s;break}e-=n.lf_left+n.piece.lineFeedCnt,i+=n.size_left+n.piece.length,n=n.right}n=n.next();while(n!==SENTINEL){if(n.piece.lineFeedCnt>0){const e=this.getAccumulatedValue(n,0),i=this.offsetOfNode(n);return{node:n,remainder:Math.min(t-1,e),nodeStartOffset:i}}if(n.piece.length>=t-1){const e=this.offsetOfNode(n);return{node:n,remainder:t-1,nodeStartOffset:e}}t-=n.piece.length,n=n.next()}return null}nodeCharCodeAt(e,t){if(e.piece.lineFeedCnt<1)return-1;const n=this._buffers[e.piece.bufferIndex],i=this.offsetInBuffer(e.piece.bufferIndex,e.piece.start)+t;return n.buffer.charCodeAt(i)}offsetOfNode(e){if(!e)return 0;let t=e.size_left;while(e!==this.root)e.parent.right===e&&(t+=e.parent.size_left+e.parent.piece.length),e=e.parent;return t}shouldCheckCRLF(){return!(this._EOLNormalized&&"\n"===this._EOL)}startWithLF(e){if("string"===typeof e)return 10===e.charCodeAt(0);if(e===SENTINEL||0===e.piece.lineFeedCnt)return!1;const t=e.piece,n=this._buffers[t.bufferIndex].lineStarts,i=t.start.line,s=n[i]+t.start.column;if(i===n.length-1)return!1;const r=n[i+1];return!(r>s+1)&&10===this._buffers[t.bufferIndex].buffer.charCodeAt(s)}endWithCR(e){return"string"===typeof e?13===e.charCodeAt(e.length-1):e!==SENTINEL&&0!==e.piece.lineFeedCnt&&13===this.nodeCharCodeAt(e,e.piece.length-1)}validateCRLFWithPrevNode(e){if(this.shouldCheckCRLF()&&this.startWithLF(e)){const t=e.prev();this.endWithCR(t)&&this.fixCRLF(t,e)}}validateCRLFWithNextNode(e){if(this.shouldCheckCRLF()&&this.endWithCR(e)){const t=e.next();this.startWithLF(t)&&this.fixCRLF(e,t)}}fixCRLF(e,t){const n=[],i=this._buffers[e.piece.bufferIndex].lineStarts;let s;s=0===e.piece.end.column?{line:e.piece.end.line-1,column:i[e.piece.end.line]-i[e.piece.end.line-1]-1}:{line:e.piece.end.line,column:e.piece.end.column-1};const r=e.piece.length-1,f=e.piece.lineFeedCnt-1;e.piece=new Piece(e.piece.bufferIndex,e.piece.start,s,f,r),updateTreeMetadata(this,e,-1,-1),0===e.piece.length&&n.push(e);const h={line:t.piece.start.line+1,column:0},l=t.piece.length-1,o=this.getLineFeedCnt(t.piece.bufferIndex,h,t.piece.end);t.piece=new Piece(t.piece.bufferIndex,h,t.piece.end,o,l),updateTreeMetadata(this,t,-1,-1),0===t.piece.length&&n.push(t);const u=this.createNewPieces("\r\n");this.rbInsertRight(e,u[0]);for(let a=0;a<n.length;a++)rbDelete(this,n[a])}adjustCarriageReturnFromNext(e,t){if(this.shouldCheckCRLF()&&this.endWithCR(e)){const n=t.next();if(this.startWithLF(n)){if(e+="\n",1===n.piece.length)rbDelete(this,n);else{const e=n.piece,t={line:e.start.line+1,column:0},i=e.length-1,s=this.getLineFeedCnt(e.bufferIndex,t,e.end);n.piece=new Piece(e.bufferIndex,t,e.end,s,i),updateTreeMetadata(this,n,-1,-1)}return!0}}return!1}iterate(e,t){if(e===SENTINEL)return t(SENTINEL);const n=this.iterate(e.left,t);return n?t(e)&&this.iterate(e.right,t):n}getNodeContent(e){if(e===SENTINEL)return"";const t=this._buffers[e.piece.bufferIndex];let n;const i=e.piece,s=this.offsetInBuffer(i.bufferIndex,i.start),r=this.offsetInBuffer(i.bufferIndex,i.end);return n=t.buffer.substring(s,r),n}getPieceContent(e){const t=this._buffers[e.bufferIndex],n=this.offsetInBuffer(e.bufferIndex,e.start),i=this.offsetInBuffer(e.bufferIndex,e.end),s=t.buffer.substring(n,i);return s}rbInsertRight(e,t){const n=new TreeNode(t,1);n.left=SENTINEL,n.right=SENTINEL,n.parent=SENTINEL,n.size_left=0,n.lf_left=0;const i=this.root;if(i===SENTINEL)this.root=n,n.color=0;else if(e.right===SENTINEL)e.right=n,n.parent=e;else{const t=leftest(e.right);t.left=n,n.parent=t}return fixInsert(this,n),n}rbInsertLeft(e,t){const n=new TreeNode(t,1);if(n.left=SENTINEL,n.right=SENTINEL,n.parent=SENTINEL,n.size_left=0,n.lf_left=0,this.root===SENTINEL)this.root=n,n.color=0;else if(e.left===SENTINEL)e.left=n,n.parent=e;else{const t=righttest(e.left);t.right=n,n.parent=t}return fixInsert(this,n),n}}